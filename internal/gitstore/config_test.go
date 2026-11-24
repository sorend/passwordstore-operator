package gitstore_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sorend/passwordstore-operator/internal/gitstore"
)

func sshAuth() gitstore.Auth {
	return gitstore.Auth{SSH: &gitstore.SSHAuth{
		PrivateKey: []byte("key"),
		KnownHosts: "github.com ssh-ed25519 AAAA",
	}}
}

func TestConfigValidate(t *testing.T) {
	tests := map[string]struct {
		cfg     gitstore.Config
		wantErr string // empty means valid
	}{
		"anonymous https":          {cfg: gitstore.Config{URL: "https://github.com/org/repo.git"}},
		"anonymous http":           {cfg: gitstore.Config{URL: "http://gitea.svc:3000/org/repo.git"}},
		"https with port":          {cfg: gitstore.Config{URL: "https://git.example.com:8443/org/repo.git"}},
		"branch and path":          {cfg: gitstore.Config{URL: "https://h/r.git", Branch: "main", Path: "pass/secrets"}},
		"full ref as branch":       {cfg: gitstore.Config{URL: "https://h/r.git", Branch: "refs/tags/v1"}},
		"path with slashes":        {cfg: gitstore.Config{URL: "https://h/r.git", Path: "/pass/"}},
		"ssh url":                  {cfg: gitstore.Config{URL: "ssh://git@github.com/org/repo.git", Auth: sshAuth()}},
		"ssh url with port":        {cfg: gitstore.Config{URL: "ssh://git@host:2222/org/repo.git", Auth: sshAuth()}},
		"scp-style":                {cfg: gitstore.Config{URL: "git@github.com:org/repo.git", Auth: sshAuth()}},
		"scp-style, absolute path": {cfg: gitstore.Config{URL: "git@git.example.com:/srv/git/repo.git", Auth: sshAuth()}},
		"scp-style, no user":       {cfg: gitstore.Config{URL: "git.example.com:org/repo.git", Auth: sshAuth()}},
		"ssh insecure": {cfg: gitstore.Config{URL: "git@github.com:org/repo.git", Auth: gitstore.Auth{
			SSH: &gitstore.SSHAuth{PrivateKey: []byte("key"), InsecureIgnoreHostKey: true}}}},
		"token": {cfg: gitstore.Config{URL: "https://h/r.git", Auth: gitstore.Auth{
			Token: &gitstore.TokenAuth{Token: "t"}}}},
		"app": {cfg: gitstore.Config{URL: "https://github.com/o/r.git", Auth: gitstore.Auth{
			App: &gitstore.AppAuth{AppID: 1, InstallationID: 2, PrivateKey: []byte("k")}}}},
		"app with enterprise url": {cfg: gitstore.Config{URL: "https://ghe.example.com/o/r.git", Auth: gitstore.Auth{
			App: &gitstore.AppAuth{AppID: 1, InstallationID: 2, PrivateKey: []byte("k"), BaseURL: "https://ghe.example.com/api/v3"}}}},

		"empty url":       {cfg: gitstore.Config{}, wantErr: "url is empty"},
		"blank url":       {cfg: gitstore.Config{URL: "  "}, wantErr: "url is empty"},
		"file scheme":     {cfg: gitstore.Config{URL: "file:///var/run/secrets"}, wantErr: "not supported"},
		"local path":      {cfg: gitstore.Config{URL: "/var/run/secrets/kubernetes.io"}, wantErr: "not supported"},
		"git scheme":      {cfg: gitstore.Config{URL: "git://github.com/org/repo.git"}, wantErr: "not supported"},
		"password in url": {cfg: gitstore.Config{URL: "https://user:secret@h/r.git"}, wantErr: "must not contain credentials"},
		"user in url":     {cfg: gitstore.Config{URL: "https://token@h/r.git"}, wantErr: "must not contain credentials"},
		"ssh password in url": {
			cfg:     gitstore.Config{URL: "ssh://git:secret@h/r.git", Auth: sshAuth()},
			wantErr: "must not contain a password",
		},
		"ssh url without auth": {cfg: gitstore.Config{URL: "git@github.com:org/repo.git"}, wantErr: "needs ssh authentication"},
		"ssh auth on https": {
			cfg:     gitstore.Config{URL: "https://h/r.git", Auth: sshAuth()},
			wantErr: "needs an ssh or scp-style url",
		},
		"token on ssh url": {
			cfg:     gitstore.Config{URL: "ssh://git@h/r.git", Auth: gitstore.Auth{Token: &gitstore.TokenAuth{Token: "t"}}},
			wantErr: "needs ssh authentication",
		},
		"two methods": {
			cfg: gitstore.Config{URL: "https://h/r.git", Auth: gitstore.Auth{
				Token: &gitstore.TokenAuth{Token: "t"},
				App:   &gitstore.AppAuth{AppID: 1, InstallationID: 2, PrivateKey: []byte("k")}}},
			wantErr: "at most one",
		},
		"empty token": {
			cfg:     gitstore.Config{URL: "https://h/r.git", Auth: gitstore.Auth{Token: &gitstore.TokenAuth{}}},
			wantErr: "token is empty",
		},
		"ssh without key": {
			cfg: gitstore.Config{URL: "git@h:r.git", Auth: gitstore.Auth{
				SSH: &gitstore.SSHAuth{KnownHosts: "h ssh-ed25519 AAAA"}}},
			wantErr: "private key is empty",
		},
		"ssh without known hosts": {
			cfg: gitstore.Config{URL: "git@h:r.git", Auth: gitstore.Auth{
				SSH: &gitstore.SSHAuth{PrivateKey: []byte("k")}}},
			wantErr: "knownHosts is required",
		},
		"ssh with blank known hosts": {
			cfg: gitstore.Config{URL: "git@h:r.git", Auth: gitstore.Auth{
				SSH: &gitstore.SSHAuth{PrivateKey: []byte("k"), KnownHosts: " \n "}}},
			wantErr: "knownHosts is required",
		},
		"ssh known hosts and insecure": {
			cfg: gitstore.Config{URL: "git@h:r.git", Auth: gitstore.Auth{
				SSH: &gitstore.SSHAuth{PrivateKey: []byte("k"), KnownHosts: "h ssh-ed25519 AAAA", InsecureIgnoreHostKey: true}}},
			wantErr: "mutually exclusive",
		},
		"app without ids": {
			cfg: gitstore.Config{URL: "https://h/r.git", Auth: gitstore.Auth{
				App: &gitstore.AppAuth{PrivateKey: []byte("k")}}},
			wantErr: "must be positive",
		},
		"app without key": {
			cfg: gitstore.Config{URL: "https://h/r.git", Auth: gitstore.Auth{
				App: &gitstore.AppAuth{AppID: 1, InstallationID: 2}}},
			wantErr: "private key is empty",
		},
		"app with bad base url": {
			cfg: gitstore.Config{URL: "https://h/r.git", Auth: gitstore.Auth{
				App: &gitstore.AppAuth{AppID: 1, InstallationID: 2, PrivateKey: []byte("k"), BaseURL: "ftp://api"}}},
			wantErr: "baseURL",
		},
		"app base url with credentials": {
			cfg: gitstore.Config{URL: "https://h/r.git", Auth: gitstore.Auth{
				App: &gitstore.AppAuth{AppID: 1, InstallationID: 2, PrivateKey: []byte("k"), BaseURL: "https://u:p@api"}}},
			wantErr: "baseURL",
		},
		"path with parent": {cfg: gitstore.Config{URL: "https://h/r.git", Path: "../etc"}, wantErr: "segments"},
		"path with parent inside": {
			cfg: gitstore.Config{URL: "https://h/r.git", Path: "a/../b"}, wantErr: "segments",
		},
		"path with double slash": {cfg: gitstore.Config{URL: "https://h/r.git", Path: "a//b"}, wantErr: "segments"},
		"path with backslash":    {cfg: gitstore.Config{URL: "https://h/r.git", Path: `a\b`}, wantErr: "backslash"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate succeeded, want an error containing %q", tt.wantErr)
			}
			if !errors.Is(err, gitstore.ErrInvalidConfig) {
				t.Errorf("error %v is not ErrInvalidConfig", err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}
