package gpg_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sorend/passwordstore-operator/internal/gpg"
)

// These tests check that keys and messages made by the real GnuPG and pass(1) work with
// Decrypter. They run in a private GNUPGHOME and PASSWORD_STORE_DIR, and are skipped when gpg is
// not installed.

type gnupg struct {
	t    *testing.T
	bin  string
	home string
}

func newGnuPG(t *testing.T) *gnupg {
	t.Helper()
	bin, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg is not installed")
	}

	// Keep the path short: it holds a unix socket, which has a small length limit.
	home, err := os.MkdirTemp("", "gnupg")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	g := &gnupg{t: t, bin: bin, home: home}
	t.Cleanup(func() {
		// Stop the agent that gpg started for this home before removing it.
		if gpgconf, err := exec.LookPath("gpgconf"); err == nil {
			_ = exec.Command(gpgconf, "--homedir", home, "--kill", "gpg-agent").Run()
		}
		_ = os.RemoveAll(home)
	})
	return g
}

func (g *gnupg) env() []string {
	return append(os.Environ(), "GNUPGHOME="+g.home, "LC_ALL=C")
}

func (g *gnupg) run(stdin string, args ...string) []byte {
	g.t.Helper()
	full := append([]string{"--homedir", g.home, "--batch", "--no-tty", "--yes", "--pinentry-mode", "loopback"}, args...)
	cmd := exec.Command(g.bin, full...)
	cmd.Env = g.env()
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		g.t.Fatalf("gpg %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.Bytes()
}

// generate creates a key and returns its fingerprint. algo is "default" for ed25519/cv25519, which
// comes with an encryption subkey, or e.g. "rsa3072", for which one is added explicitly.
func (g *gnupg) generate(uid, algo, passphrase string) string {
	g.t.Helper()
	g.run("", "--passphrase", passphrase, "--quick-gen-key", uid, algo, "default", "never")

	out := g.run("", "--with-colons", "--fingerprint", "--list-keys", uid)
	fpr := ""
	for line := range strings.SplitSeq(string(out), "\n") {
		// The first fpr record belongs to the primary key.
		if strings.HasPrefix(line, "fpr:") {
			fpr = strings.Split(line, ":")[9]
			break
		}
	}
	if fpr == "" {
		g.t.Fatalf("no fingerprint found for %s in:\n%s", uid, out)
	}

	if algo != "default" {
		g.run("", "--passphrase", passphrase, "--quick-add-key", fpr, algo, "encr", "never")
	}
	return fpr
}

func (g *gnupg) exportSecret(fpr, passphrase string, subkeysOnly bool) []byte {
	g.t.Helper()
	flag := "--export-secret-keys"
	if subkeysOnly {
		flag = "--export-secret-subkeys"
	}
	return g.run("", "--passphrase", passphrase, "--armor", flag, fpr)
}

func (g *gnupg) encrypt(plaintext string, extra []string, recipients ...string) []byte {
	g.t.Helper()
	args := []string{"--trust-model", "always", "--encrypt"}
	for _, r := range recipients {
		args = append(args, "--recipient", r)
	}
	return g.run(plaintext, append(args, extra...)...)
}

func TestInteropGnuPGKeysAndMessages(t *testing.T) {
	g := newGnuPG(t)

	type keyCase struct {
		name, algo, passphrase string
	}
	for _, kc := range []keyCase{
		{"ed25519", "default", ""},
		{"rsa3072", "rsa3072", ""},
		{"ed25519 with passphrase", "default", "correct horse"},
		{"rsa3072 with passphrase", "rsa3072", "correct horse"},
	} {
		t.Run(kc.name, func(t *testing.T) {
			uid := "Interop <" + strings.NewReplacer(" ", "-").Replace(kc.name) + "@example.com>"
			fpr := g.generate(uid, kc.algo, kc.passphrase)

			for exportName, subkeysOnly := range map[string]bool{
				"export-secret-keys":    false,
				"export-secret-subkeys": true,
			} {
				t.Run(exportName, func(t *testing.T) {
					d, err := gpg.NewDecrypter(g.exportSecret(fpr, kc.passphrase, subkeysOnly), fpr, []byte(kc.passphrase))
					if err != nil {
						t.Fatalf("NewDecrypter: %v", err)
					}
					if d.Fingerprint() != fpr {
						t.Errorf("Fingerprint() = %s, gpg says %s", d.Fingerprint(), fpr)
					}

					const entry = "hunter2\nusername: bob\n"
					for msgName, extra := range map[string][]string{
						"binary":              nil,
						"armored":             {"--armor"},
						"no compression":      {"--compress-algo", "none"},
						"hidden recipient":    {"--throw-keyids"},
						"aes256":              {"--cipher-algo", "AES256"},
						"explicit compressed": {"--compress-algo", "zlib"},
					} {
						got, err := d.Decrypt(g.encrypt(entry, extra, fpr))
						if err != nil {
							t.Errorf("%s: Decrypt: %v", msgName, err)
							continue
						}
						if string(got) != entry {
							t.Errorf("%s: Decrypt = %q, want %q", msgName, got, entry)
						}
					}
				})
			}
		})
	}
}

func TestInteropGnuPGSelectsByEveryIDFormat(t *testing.T) {
	g := newGnuPG(t)
	fpr := g.generate("Formats <formats@example.com>", "default", "")
	secret := g.exportSecret(fpr, "", false)

	// The ID formats that people pass to "pass init".
	for name, id := range map[string]string{
		"fingerprint":    fpr,
		"0x long key id": "0x" + fpr[len(fpr)-16:],
		"long key id":    fpr[len(fpr)-16:],
		"short key id":   fpr[len(fpr)-8:],
		"email":          "formats@example.com",
	} {
		d, err := gpg.NewDecrypter(secret, id, nil)
		if err != nil {
			t.Errorf("%s (%s): %v", name, id, err)
			continue
		}
		got, err := d.Decrypt(g.encrypt("x", nil, id))
		if err != nil || string(got) != "x" {
			t.Errorf("%s: Decrypt = %q, %v", name, got, err)
		}
	}
}

func TestInteropGnuPGKeyringWithSeveralKeys(t *testing.T) {
	g := newGnuPG(t)
	mine := g.generate("Mine <mine@example.com>", "default", "")
	theirs := g.generate("Theirs <theirs@example.com>", "rsa3072", "")

	// "gpg --export-secret-keys" without an argument exports every key.
	all := g.run("", "--passphrase", "", "--armor", "--export-secret-keys")

	d, err := gpg.NewDecrypter(all, mine, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Fingerprint() != mine {
		t.Fatalf("selected %s, want %s", d.Fingerprint(), mine)
	}
	if got, err := d.Decrypt(g.encrypt("for me", nil, mine)); err != nil || string(got) != "for me" {
		t.Fatalf("Decrypt = %q, %v", got, err)
	}
	if _, err := d.Decrypt(g.encrypt("for them", nil, theirs)); err == nil {
		t.Fatal("a message for another key must not decrypt")
	}
}

func TestInteropPass(t *testing.T) {
	g := newGnuPG(t)
	passBin, err := exec.LookPath("pass")
	if err != nil {
		t.Skip("pass is not installed")
	}
	fpr := g.generate("Pass <pass@example.com>", "default", "")

	storeDir := filepath.Join(t.TempDir(), "store")
	runPass := func(stdin string, args ...string) {
		t.Helper()
		cmd := exec.Command(passBin, args...)
		// Never touch the password store or keyring of the person running the tests.
		cmd.Env = append(g.env(), "PASSWORD_STORE_DIR="+storeDir, "PASSWORD_STORE_GPG_OPTS=--homedir "+g.home)
		cmd.Stdin = strings.NewReader(stdin)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("pass %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	runPass("", "init", fpr)
	runPass("s3cr3t\n", "insert", "--echo", "k8s/postgres.db.svc/admin-user")
	runPass("line one\nline two\nusername: bob\n", "insert", "--multiline", "k8s/multi")

	d, err := gpg.NewDecrypter(g.exportSecret(fpr, "", false), fpr, nil)
	if err != nil {
		t.Fatal(err)
	}

	for file, want := range map[string]string{
		"k8s/postgres.db.svc/admin-user.gpg": "s3cr3t\n",
		"k8s/multi.gpg":                      "line one\nline two\nusername: bob\n",
	} {
		data, err := os.ReadFile(filepath.Join(storeDir, file))
		if err != nil {
			t.Fatal(err)
		}
		got, err := d.Decrypt(data)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", file, got, want)
		}
	}

	gpgID, err := os.ReadFile(filepath.Join(storeDir, ".gpg-id"))
	if err != nil || strings.TrimSpace(string(gpgID)) != fpr {
		t.Errorf(".gpg-id = %q, %v; want %s", gpgID, err, fpr)
	}
}

// A store can give the cluster access to one folder only: "pass init -p folder" gives the folder
// its own .gpg-id, and the entries in it are encrypted to the key of the cluster as well. This is
// what the documentation recommends, so it is checked with the real pass.
func TestInteropPassSubfolderForTheCluster(t *testing.T) {
	g := newGnuPG(t)
	passBin, err := exec.LookPath("pass")
	if err != nil {
		t.Skip("pass is not installed")
	}
	me := g.generate("Me <me@example.com>", "default", "")
	cluster := g.generate("Cluster <cluster@example.com>", "default", "")

	storeDir := filepath.Join(t.TempDir(), "store")
	runPass := func(stdin string, args ...string) {
		t.Helper()
		cmd := exec.Command(passBin, args...)
		cmd.Env = append(g.env(), "PASSWORD_STORE_DIR="+storeDir, "PASSWORD_STORE_GPG_OPTS=--homedir "+g.home)
		cmd.Stdin = strings.NewReader(stdin)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("pass %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	runPass("", "init", me)                       // the whole store is for me
	runPass("", "init", "-p", "k8s", me, cluster) // the folder k8s is for me and the cluster
	runPass("private\n", "insert", "--echo", "bank/password")
	runPass("shared\n", "insert", "--echo", "k8s/db/password")

	secret := g.exportSecret(cluster, "", false)
	d, err := gpg.NewDecrypter(secret, cluster, nil)
	if err != nil {
		t.Fatal(err)
	}

	inFolder, err := os.ReadFile(filepath.Join(storeDir, "k8s/db/password.gpg"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := d.Decrypt(inFolder); err != nil || string(got) != "shared\n" {
		t.Errorf("the entry in the folder of the cluster: %q, %v", got, err)
	}

	outside, err := os.ReadFile(filepath.Join(storeDir, "bank/password.gpg"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Decrypt(outside); !errors.Is(err, gpg.ErrNotRecipient) {
		t.Errorf("the key of the cluster must not open entries outside of its folder, got err = %v", err)
	}

	// The folder has its own .gpg-id, with both keys.
	ids, err := os.ReadFile(filepath.Join(storeDir, "k8s/.gpg-id"))
	if err != nil || !strings.Contains(string(ids), me) || !strings.Contains(string(ids), cluster) {
		t.Errorf("k8s/.gpg-id = %q, %v", ids, err)
	}
}
