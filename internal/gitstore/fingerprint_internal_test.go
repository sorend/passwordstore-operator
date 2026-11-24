package gitstore

import "testing"

func TestFingerprint(t *testing.T) {
	base := Config{
		URL:    "https://github.com/org/repo.git",
		Branch: "main",
		Auth: Auth{Token: &TokenAuth{
			Username: "user",
			Token:    "token",
		}},
	}

	first, second := base.fingerprint(), base.fingerprint()
	if first != second {
		t.Fatal("fingerprint is not deterministic")
	}

	// Everything that decides what is fetched must change the fingerprint.
	changes := map[string]func(c *Config){
		"url":            func(c *Config) { c.URL = "https://github.com/org/other.git" },
		"branch":         func(c *Config) { c.Branch = "dev" },
		"token":          func(c *Config) { c.Auth.Token = &TokenAuth{Username: "user", Token: "other"} },
		"token username": func(c *Config) { c.Auth.Token = &TokenAuth{Username: "other", Token: "token"} },
		"no auth":        func(c *Config) { c.Auth = Auth{} },
		"ssh key": func(c *Config) {
			c.Auth = Auth{SSH: &SSHAuth{PrivateKey: []byte("a"), KnownHosts: "h"}}
		},
		"ssh passphrase": func(c *Config) {
			c.Auth = Auth{SSH: &SSHAuth{PrivateKey: []byte("a"), Passphrase: []byte("p"), KnownHosts: "h"}}
		},
		"ssh known hosts": func(c *Config) {
			c.Auth = Auth{SSH: &SSHAuth{PrivateKey: []byte("a"), KnownHosts: "other"}}
		},
		"ssh insecure": func(c *Config) {
			c.Auth = Auth{SSH: &SSHAuth{PrivateKey: []byte("a"), InsecureIgnoreHostKey: true}}
		},
		"app id":           func(c *Config) { c.Auth = Auth{App: &AppAuth{AppID: 1, InstallationID: 2, PrivateKey: []byte("k")}} },
		"app installation": func(c *Config) { c.Auth = Auth{App: &AppAuth{AppID: 1, InstallationID: 3, PrivateKey: []byte("k")}} },
		"app key":          func(c *Config) { c.Auth = Auth{App: &AppAuth{AppID: 1, InstallationID: 2, PrivateKey: []byte("j")}} },
		"app base url": func(c *Config) {
			c.Auth = Auth{App: &AppAuth{AppID: 1, InstallationID: 2, PrivateKey: []byte("k"), BaseURL: "https://x"}}
		},
	}
	seen := map[string]string{base.fingerprint(): "base"}
	for name, change := range changes {
		c := base
		change(&c)
		fp := c.fingerprint()
		if previous, dup := seen[fp]; dup {
			t.Errorf("changing %s gives the same fingerprint as %s", name, previous)
		}
		seen[fp] = name
	}

	t.Run("path is not part of it", func(t *testing.T) {
		c := base
		c.Path = "some/directory"
		if c.fingerprint() != base.fingerprint() {
			t.Error("a different path must not invalidate the clone")
		}
	})

	t.Run("fields cannot run into each other", func(t *testing.T) {
		a := Config{URL: "ab", Branch: "c"}
		b := Config{URL: "a", Branch: "bc"}
		if a.fingerprint() == b.fingerprint() {
			t.Error("fingerprints of (ab, c) and (a, bc) collide")
		}
	})
}
