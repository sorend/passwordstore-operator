package gitstore_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sorend/passwordstore-operator/internal/gitstore"
	"github.com/sorend/passwordstore-operator/internal/testutil"
)

// The operator has no setting for a private certificate authority. A Git server behind one is
// supported by giving the operator the certificate through the environment, which is how every Go
// program does it. This test checks what the documentation says about that: SSL_CERT_DIR adds a
// certificate to the ones that are trusted, and a server that is not trusted is refused.
//
// The roots are read once per process, so the check runs in a process of its own.
const privateCAHelperEnv = "GITSTORE_PRIVATE_CA_URL"

func TestPrivateCAHelperProcess(t *testing.T) {
	url := os.Getenv(privateCAHelperEnv)
	if url == "" {
		t.Skip("only runs as the subprocess of TestPrivateCA")
	}
	_, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", gitstore.Config{URL: url}, 0)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
}

func TestPrivateCA(t *testing.T) {
	server := testutil.NewGitServer(t, testutil.WithTLS())
	server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("x")})

	caDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(caDir, "private-ca.pem"), server.Certificate(), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(env ...string) (string, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPrivateCAHelperProcess$", "-test.v")
		cmd.Env = append(os.Environ(), append([]string{privateCAHelperEnv + "=" + server.URL}, env...)...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	t.Run("a server with a certificate that nobody trusts is refused", func(t *testing.T) {
		out, err := run("SSL_CERT_DIR=" + t.TempDir())
		if err == nil {
			t.Fatalf("expected the certificate to be refused:\n%s", out)
		}
		if !strings.Contains(out, "certificate") {
			t.Errorf("expected a certificate error, got:\n%s", out)
		}
	})

	t.Run("SSL_CERT_DIR makes a certificate authority trusted", func(t *testing.T) {
		if out, err := run("SSL_CERT_DIR=" + caDir); err != nil {
			t.Fatalf("the server must be trusted through SSL_CERT_DIR: %v\n%s", err, out)
		}
	})
}
