// Package gitstore fetches password stores from Git repositories and reads files from them.
//
// A repository is cloned into memory with a depth of one commit, so nothing is written to disk
// and the encrypted entries only live in the memory of the operator. The result of a fetch is an
// immutable Snapshot of one commit, so the entries read for one Secret are always consistent
// with each other, even while another fetch is running.
package gitstore

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/transport"
)

// The schemes of the URLs of repositories that are supported.
const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
	schemeSSH   = "ssh"
)

const (
	// DefaultTokenUsername is the user name sent with a token when none is configured.
	DefaultTokenUsername = "x-access-token"
	// DefaultGitHubAPI is the GitHub API used to exchange a GitHub App JWT for a token.
	DefaultGitHubAPI = "https://api.github.com"
	// DefaultSSHUser is the SSH user when the URL does not name one.
	DefaultSSHUser = "git"
)

// ErrInvalidConfig means a Config is not usable.
var ErrInvalidConfig = errors.New("invalid repository configuration")

// Config describes a repository that holds a password store.
type Config struct {
	// URL of the repository: https://, http://, ssh:// or scp-style.
	URL string
	// Branch to read. Empty selects the default branch of the remote. A name that starts
	// with "refs/" is used as it is, for example refs/tags/v1.
	Branch string
	// Path of the password store inside the repository. Empty is the root.
	Path string
	// Auth holds the credentials. At most one method can be set.
	Auth Auth
}

// Auth holds the credentials for one authentication method.
type Auth struct {
	SSH   *SSHAuth
	Token *TokenAuth
	App   *AppAuth
}

// SSHAuth authenticates with an SSH private key.
type SSHAuth struct {
	// PrivateKey in PEM or OpenSSH format.
	PrivateKey []byte
	// Passphrase of PrivateKey, if it is encrypted.
	Passphrase []byte
	// KnownHosts holds the accepted host keys in known_hosts format.
	KnownHosts string
	// InsecureIgnoreHostKey accepts any host key. It excludes KnownHosts.
	InsecureIgnoreHostKey bool
}

// TokenAuth authenticates over http(s) with a token sent as the basic auth password.
type TokenAuth struct {
	// Username defaults to DefaultTokenUsername.
	Username string
	Token    string
}

// AppAuth authenticates as an installation of a GitHub App.
type AppAuth struct {
	AppID          int64
	InstallationID int64
	// PrivateKey of the App in PEM format.
	PrivateKey []byte
	// BaseURL of the GitHub API, DefaultGitHubAPI if empty.
	BaseURL string
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, args...))
}

// endpoint parses the URL of the repository.
func (c Config) endpoint() (*transport.Endpoint, error) {
	ep, err := transport.NewEndpoint(c.URL)
	if err != nil {
		return nil, invalid("url %q: %v", c.URL, err)
	}
	return ep, nil
}

// Validate checks that the configuration is consistent and only uses what is supported.
func (c Config) Validate() error {
	if strings.TrimSpace(c.URL) == "" {
		return invalid("url is empty")
	}
	ep, err := c.endpoint()
	if err != nil {
		return err
	}

	switch ep.Protocol {
	case schemeHTTP, schemeHTTPS, schemeSSH:
	default:
		// This also keeps file:// out, which would read from the filesystem of the operator.
		return invalid("url scheme %q is not supported, use https, http or ssh", ep.Protocol)
	}
	if ep.Protocol != schemeSSH && (ep.User != "" || ep.Password != "") {
		return invalid("the url must not contain credentials, configure auth instead")
	}
	if ep.Protocol == schemeSSH && ep.Password != "" {
		return invalid("the url must not contain a password, configure auth instead")
	}

	auths := 0
	for _, set := range []bool{c.Auth.SSH != nil, c.Auth.Token != nil, c.Auth.App != nil} {
		if set {
			auths++
		}
	}
	if auths > 1 {
		return invalid("at most one of ssh, token or app can be used")
	}

	switch {
	case c.Auth.SSH != nil:
		if ep.Protocol != schemeSSH {
			return invalid("ssh authentication needs an ssh or scp-style url")
		}
		if err := c.Auth.SSH.validate(); err != nil {
			return err
		}
	case ep.Protocol == schemeSSH:
		return invalid("an ssh url needs ssh authentication")
	case c.Auth.Token != nil:
		if c.Auth.Token.Token == "" {
			return invalid("token is empty")
		}
	case c.Auth.App != nil:
		if err := c.Auth.App.validate(); err != nil {
			return err
		}
	}

	if c.Path != "" {
		if err := validateRepoPath(c.Path); err != nil {
			return err
		}
	}
	return nil
}

func (a *SSHAuth) validate() error {
	if len(a.PrivateKey) == 0 {
		return invalid("ssh private key is empty")
	}
	known := strings.TrimSpace(a.KnownHosts) != ""
	switch {
	case a.InsecureIgnoreHostKey && known:
		return invalid("knownHosts and insecureIgnoreHostKey are mutually exclusive")
	case !a.InsecureIgnoreHostKey && !known:
		return invalid("knownHosts is required unless insecureIgnoreHostKey is set")
	}
	return nil
}

func (a *AppAuth) validate() error {
	if a.AppID <= 0 || a.InstallationID <= 0 {
		return invalid("app and installation IDs must be positive")
	}
	if len(a.PrivateKey) == 0 {
		return invalid("github app private key is empty")
	}
	if a.BaseURL != "" {
		u, err := url.Parse(a.BaseURL)
		if err != nil || (u.Scheme != schemeHTTPS && u.Scheme != schemeHTTP) || u.Host == "" || u.User != nil {
			return invalid("github app baseURL %q must be an http(s) URL without credentials", a.BaseURL)
		}
	}
	return nil
}

// validateRepoPath checks a directory path inside the repository.
func validateRepoPath(p string) error {
	if strings.ContainsAny(p, "\\\x00") {
		return invalid("path %q contains a backslash or NUL", p)
	}
	for segment := range strings.SplitSeq(strings.Trim(p, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return invalid("path %q must not contain empty, \".\" or \"..\" segments", p)
		}
	}
	return nil
}

// cleanPath returns the path of the store with surrounding slashes removed.
func (c Config) cleanPath() string {
	if c.Path == "" {
		return ""
	}
	return path.Clean(strings.Trim(c.Path, "/"))
}

// fingerprint identifies everything that decides which content is fetched: when it changes, a
// cached clone must not be used. It includes credentials, because a different identity can see
// different content. The Path is left out, it only selects a directory of the clone.
func (c Config) fingerprint() string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			_ = binary.Write(h, binary.BigEndian, uint64(len(p)))
			h.Write([]byte(p))
		}
	}
	write(c.URL, c.Branch)
	if a := c.Auth.SSH; a != nil {
		write(schemeSSH, string(a.PrivateKey), string(a.Passphrase), a.KnownHosts, strconv.FormatBool(a.InsecureIgnoreHostKey))
	}
	if a := c.Auth.Token; a != nil {
		write("token", a.Username, a.Token)
	}
	if a := c.Auth.App; a != nil {
		write("app", strconv.FormatInt(a.AppID, 10), strconv.FormatInt(a.InstallationID, 10), string(a.PrivateKey), a.BaseURL)
	}
	return hex.EncodeToString(h.Sum(nil))
}
