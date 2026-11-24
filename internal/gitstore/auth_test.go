package gitstore_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	xknownhosts "golang.org/x/crypto/ssh/knownhosts"

	"github.com/sorend/passwordstore-operator/internal/gitstore"
	"github.com/sorend/passwordstore-operator/internal/testutil"
)

func tokenCfg(url, username, token string) gitstore.Config {
	return gitstore.Config{URL: url, Auth: gitstore.Auth{Token: &gitstore.TokenAuth{Username: username, Token: token}}}
}

func TestTokenAuth(t *testing.T) {
	server := testutil.NewGitServer(t, testutil.WithBasicAuth("x-access-token", "s3cr3t-token"))
	server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("v1")})
	m := newManager(gitstore.Options{})

	t.Run("default user name", func(t *testing.T) {
		snap := mustSync(t, m, "default-user", tokenCfg(server.URL, "", "s3cr3t-token"), 0)
		if got := mustRead(t, snap, "a.gpg"); got != "v1" {
			t.Errorf("a.gpg = %q", got)
		}
	})

	t.Run("wrong token fails and does not leak", func(t *testing.T) {
		_, err := m.Sync(context.Background(), "wrong", tokenCfg(server.URL, "", "wrong-token-value"), 0)
		if err == nil {
			t.Fatal("expected an error")
		}
		if strings.Contains(err.Error(), "wrong-token-value") {
			t.Errorf("the error contains the token: %v", err)
		}
	})

	t.Run("no credentials", func(t *testing.T) {
		_, err := m.Sync(context.Background(), "anonymous", gitstore.Config{URL: server.URL}, 0)
		if err == nil || !strings.Contains(err.Error(), "authentication required") {
			t.Fatalf("err = %v, want authentication required", err)
		}
	})

	t.Run("wrong user name", func(t *testing.T) {
		if _, err := m.Sync(context.Background(), "wrong-user", tokenCfg(server.URL, "someone", "s3cr3t-token"), 0); err == nil {
			t.Fatal("expected an error for a user name the server does not accept")
		}
	})

	t.Run("custom user name", func(t *testing.T) {
		custom := testutil.NewGitServer(t, testutil.WithBasicAuth("oauth2", "tok"))
		custom.Commit(t, "init", map[string][]byte{"a.gpg": []byte("custom")})
		snap := mustSync(t, m, "custom-user", tokenCfg(custom.URL, "oauth2", "tok"), 0)
		if got := mustRead(t, snap, "a.gpg"); got != "custom" {
			t.Errorf("a.gpg = %q", got)
		}
	})
}

type githubFixture struct {
	git    *testutil.GitServer
	github *testutil.FakeGitHubApp
	cfg    gitstore.Config
}

func newGitHubFixture(t *testing.T) *githubFixture {
	t.Helper()
	pemKey, key := testutil.NewRSAKeyPEM(t)
	github := testutil.NewFakeGitHubApp(t, 4242, 99, &key.PublicKey)
	server := testutil.NewGitServer(t, testutil.WithAuth(func(user, password string) bool {
		return user == "x-access-token" && github.IsValidToken(password)
	}))
	server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("from a private repo")})

	return &githubFixture{git: server, github: github, cfg: gitstore.Config{
		URL: server.URL,
		Auth: gitstore.Auth{App: &gitstore.AppAuth{
			AppID: 4242, InstallationID: 99, PrivateKey: pemKey, BaseURL: github.URL,
		}},
	}}
}

func TestGitHubAppAuth(t *testing.T) {
	t.Run("exchanges a signed JWT for a token that clones", func(t *testing.T) {
		f := newGitHubFixture(t)
		snap := mustSync(t, newManager(gitstore.Options{}), "s", f.cfg, 0)
		if got := mustRead(t, snap, "a.gpg"); got != "from a private repo" {
			t.Errorf("a.gpg = %q", got)
		}
		if f.github.Requests() != 1 {
			t.Errorf("%d token requests, want 1", f.github.Requests())
		}
	})

	t.Run("reuses the token while it is valid", func(t *testing.T) {
		f := newGitHubFixture(t)
		m := newManager(gitstore.Options{})
		for range 4 {
			mustSync(t, m, "s", f.cfg, 0)
		}
		if f.github.Requests() != 1 {
			t.Errorf("%d token requests for four syncs, want the token to be reused", f.github.Requests())
		}
	})

	t.Run("replaces a token that is about to expire", func(t *testing.T) {
		f := newGitHubFixture(t)
		f.github.SetTokenLifetime(2 * time.Minute) // less than the refresh margin
		m := newManager(gitstore.Options{})
		mustSync(t, m, "s", f.cfg, 0)
		first := f.github.LastToken()
		mustSync(t, m, "s", f.cfg, 0)
		if f.github.Requests() != 2 || f.github.LastToken() == first {
			t.Errorf("%d token requests, want a new token for a token that expires soon", f.github.Requests())
		}
	})

	t.Run("replaces an expired token when time passes", func(t *testing.T) {
		f := newGitHubFixture(t)
		clock := newClock()
		f.github.SetClock(clock.Now)
		m := newManager(gitstore.Options{Now: clock.Now})
		mustSync(t, m, "s", f.cfg, 0)
		clock.Advance(3 * time.Hour)
		mustSync(t, m, "s", f.cfg, 0)
		if f.github.Requests() != 2 {
			t.Errorf("%d token requests, want 2 after the token expired", f.github.Requests())
		}
	})

	t.Run("github rejects the app", func(t *testing.T) {
		f := newGitHubFixture(t)
		f.github.Fail(404, "Integration not found")
		_, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", f.cfg, 0)
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, want := range []string{"404", "Integration not found", "4242", "99"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	})

	t.Run("jwt signed by another key", func(t *testing.T) {
		f := newGitHubFixture(t)
		otherPEM, _ := testutil.NewRSAKeyPEM(t)
		f.cfg.Auth.App.PrivateKey = otherPEM
		_, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", f.cfg, 0)
		if err == nil || !strings.Contains(err.Error(), "401") {
			t.Fatalf("err = %v, want the 401 of github", err)
		}
	})

	t.Run("wrong app id", func(t *testing.T) {
		f := newGitHubFixture(t)
		f.cfg.Auth.App.AppID = 1
		if _, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", f.cfg, 0); err == nil {
			t.Fatal("a JWT for another app must be rejected")
		}
	})

	t.Run("private key that is not a key", func(t *testing.T) {
		f := newGitHubFixture(t)
		f.cfg.Auth.App.PrivateKey = []byte("not a key")
		_, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", f.cfg, 0)
		if err == nil || !strings.Contains(err.Error(), "github app private key") {
			t.Fatalf("err = %v", err)
		}
		if f.github.Requests() != 0 {
			t.Error("nothing must be requested with an unusable key")
		}
	})

	t.Run("base url with trailing slash", func(t *testing.T) {
		f := newGitHubFixture(t)
		f.cfg.Auth.App.BaseURL += "/"
		mustSync(t, newManager(gitstore.Options{}), "s", f.cfg, 0)
	})

	t.Run("a repository that the installation cannot read", func(t *testing.T) {
		f := newGitHubFixture(t)
		other := testutil.NewGitServer(t, testutil.WithBasicAuth("x-access-token", "something-else"))
		other.Commit(t, "init", map[string][]byte{"a.gpg": []byte("x")})
		f.cfg.URL = other.URL
		if _, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", f.cfg, 0); err == nil {
			t.Fatal("expected an error")
		}
	})
}

type sshFixture struct {
	git    *testutil.GitServer
	server *testutil.SSHServer
	key    *testutil.SSHKey
}

func newSSHFixture(t *testing.T, opts ...testutil.SSHKeyOption) *sshFixture {
	t.Helper()
	git := testutil.NewGitServer(t)
	git.Commit(t, "init", map[string][]byte{"a.gpg": []byte("over ssh")})
	key := testutil.NewSSHKey(t, opts...)
	return &sshFixture{git: git, server: testutil.NewSSHServer(t, git.Root, key.Public), key: key}
}

func (f *sshFixture) cfg() gitstore.Config {
	return gitstore.Config{URL: f.server.URL("store"), Auth: gitstore.Auth{SSH: &gitstore.SSHAuth{
		PrivateKey: f.key.Private,
		Passphrase: []byte(f.key.Passphrase),
		KnownHosts: f.server.KnownHosts,
	}}}
}

func TestSSHAuth(t *testing.T) {
	t.Run("ed25519 key in openssh format", func(t *testing.T) {
		f := newSSHFixture(t)
		snap := mustSync(t, newManager(gitstore.Options{}), "s", f.cfg(), 0)
		if got := mustRead(t, snap, "a.gpg"); got != "over ssh" {
			t.Errorf("a.gpg = %q", got)
		}
		if f.server.Sessions() == 0 {
			t.Error("the repository was not fetched over ssh")
		}
	})

	t.Run("rsa key in pem format", func(t *testing.T) {
		f := newSSHFixture(t, testutil.WithRSAPEM())
		mustSync(t, newManager(gitstore.Options{}), "s", f.cfg(), 0)
	})

	t.Run("key with a passphrase", func(t *testing.T) {
		f := newSSHFixture(t, testutil.WithSSHPassphrase("open sesame"))
		mustSync(t, newManager(gitstore.Options{}), "s", f.cfg(), 0)
	})

	t.Run("rsa pem key with a passphrase", func(t *testing.T) {
		f := newSSHFixture(t, testutil.WithRSAPEM(), testutil.WithSSHPassphrase("open sesame"))
		mustSync(t, newManager(gitstore.Options{}), "s", f.cfg(), 0)
	})

	t.Run("passphrase that is not needed", func(t *testing.T) {
		f := newSSHFixture(t)
		cfg := f.cfg()
		cfg.Auth.SSH.Passphrase = []byte("unused")
		mustSync(t, newManager(gitstore.Options{}), "s", cfg, 0)
	})

	t.Run("missing passphrase", func(t *testing.T) {
		f := newSSHFixture(t, testutil.WithSSHPassphrase("open sesame"))
		cfg := f.cfg()
		cfg.Auth.SSH.Passphrase = nil
		_, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", cfg, 0)
		if err == nil || !strings.Contains(err.Error(), "ssh private key") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("wrong passphrase", func(t *testing.T) {
		f := newSSHFixture(t, testutil.WithSSHPassphrase("open sesame"))
		cfg := f.cfg()
		cfg.Auth.SSH.Passphrase = []byte("wrong")
		if _, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", cfg, 0); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("private key that is not a key", func(t *testing.T) {
		f := newSSHFixture(t)
		cfg := f.cfg()
		cfg.Auth.SSH.PrivateKey = []byte("garbage")
		_, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", cfg, 0)
		if err == nil || !strings.Contains(err.Error(), "ssh private key") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("key that the server does not know", func(t *testing.T) {
		f := newSSHFixture(t)
		cfg := f.cfg()
		cfg.Auth.SSH.PrivateKey = testutil.NewSSHKey(t).Private
		if _, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", cfg, 0); err == nil {
			t.Fatal("expected an error for an unauthorized key")
		}
	})
}

func TestSSHHostKeyVerification(t *testing.T) {
	f := newSSHFixture(t)
	m := newManager(gitstore.Options{})
	addr := fmt.Sprintf("[%s]:%d", f.server.Host, f.server.Port)

	t.Run("server that offers several host key types", func(t *testing.T) {
		// known_hosts only lists the ed25519 key, but the server also has an ECDSA key.
		// Without limiting the algorithms to the ones in known_hosts the handshake can pick
		// the ECDSA key and fail with a key mismatch.
		for i := range 5 {
			mustSync(t, m, fmt.Sprintf("multi-%d", i), f.cfg(), 0)
		}
	})

	t.Run("known_hosts with comments, blank lines and other hosts", func(t *testing.T) {
		cfg := f.cfg()
		cfg.Auth.SSH.KnownHosts = "# my servers\n\ngithub.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n" +
			f.server.KnownHosts + "\n"
		mustSync(t, m, "comments", cfg, 0)
	})

	t.Run("hashed host names", func(t *testing.T) {
		cfg := f.cfg()
		cfg.Auth.SSH.KnownHosts = xknownhosts.HashHostname(addr) + " " + strings.SplitN(f.server.KnownHosts, " ", 2)[1]
		mustSync(t, m, "hashed", cfg, 0)
	})

	t.Run("a different host key is refused", func(t *testing.T) {
		other := testutil.NewSSHKey(t)
		cfg := f.cfg()
		cfg.Auth.SSH.KnownHosts = xknownhosts.Line([]string{addr}, other.Public)
		_, err := m.Sync(context.Background(), "mismatch", cfg, 0)
		if err == nil {
			t.Fatal("a server with another host key than in knownHosts must be refused")
		}
		if !strings.Contains(err.Error(), "does not match knownHosts") {
			t.Errorf("error %q has no hint about the mismatch", err)
		}
	})

	t.Run("a host that is not in known_hosts is refused", func(t *testing.T) {
		cfg := f.cfg()
		cfg.Auth.SSH.KnownHosts = xknownhosts.Line([]string{"[192.0.2.1]:22"}, f.server.HostKey)
		_, err := m.Sync(context.Background(), "unknown", cfg, 0)
		if err == nil {
			t.Fatal("an unknown host must be refused")
		}
		if !strings.Contains(err.Error(), "not in knownHosts") {
			t.Errorf("error %q has no hint about the missing host", err)
		}
	})

	t.Run("ignoring the host key accepts any server", func(t *testing.T) {
		cfg := f.cfg()
		cfg.Auth.SSH.KnownHosts = ""
		cfg.Auth.SSH.InsecureIgnoreHostKey = true
		mustSync(t, m, "insecure", cfg, 0)
	})

	t.Run("garbage in known_hosts", func(t *testing.T) {
		cfg := f.cfg()
		cfg.Auth.SSH.KnownHosts = "this is not a known_hosts line"
		_, err := m.Sync(context.Background(), "garbage", cfg, 0)
		if err == nil || !strings.Contains(err.Error(), "knownHosts") {
			t.Fatalf("err = %v, want an error about knownHosts", err)
		}
	})
}
