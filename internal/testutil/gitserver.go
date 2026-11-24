package testutil

import (
	"encoding/pem"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// repoName is the directory of the served repository below the root of the server.
const repoName = "store"

// GitServer serves a Git repository over HTTP with the real "git http-backend", and lets the test
// make commits to it. The test is skipped when git is not installed.
type GitServer struct {
	// URL is the URL to clone the repository from.
	URL string
	// Root is the directory that holds the repository, which is Root/store. The SSH server
	// serves the same directory.
	Root string

	repo   *git.Repository
	server *httptest.Server

	// refs makes the update of a reference atomic for the clients of the server. A real Git server
	// does not show a reference that is half written, and go-git writes one by emptying the file
	// first, so a client that asks at that moment would be told that there is no HEAD.
	refs sync.RWMutex

	mu       sync.Mutex
	requests []string
}

type gitServerConfig struct {
	auth   func(user, password string) bool
	listen string
	tls    bool
}

// GitServerOption customizes NewGitServer.
type GitServerOption func(*gitServerConfig)

// WithBasicAuth makes the server require HTTP basic auth with the given credentials.
func WithBasicAuth(user, password string) GitServerOption {
	return WithAuth(func(u, p string) bool { return u == user && p == password })
}

// WithAuth makes the server require HTTP basic auth that the function accepts.
func WithAuth(accept func(user, password string) bool) GitServerOption {
	return func(c *gitServerConfig) { c.auth = accept }
}

// WithListenAddress makes the server listen on the address, for example "0.0.0.0:0", instead of
// only on the loopback interface. It is for tests that need clients in other network namespaces,
// such as the nodes of a kind cluster, to reach the server. Use HostURL to get a URL for them.
func WithListenAddress(addr string) GitServerOption {
	return func(c *gitServerConfig) { c.listen = addr }
}

// WithTLS makes the server speak https, with a certificate that is not signed by a certificate
// authority that clients trust. Certificate returns it, to be trusted for a test.
func WithTLS() GitServerOption {
	return func(c *gitServerConfig) { c.tls = true }
}

// NewGitServer creates an empty repository with the default branch "main" and serves it.
func NewGitServer(t TB, opts ...GitServerOption) *GitServer {
	t.Helper()

	var cfg gitServerConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}

	root := t.TempDir()
	repo, err := git.PlainInitWithOptions(filepath.Join(root, repoName), &git.PlainInitOptions{
		InitOptions: git.InitOptions{DefaultBranch: plumbing.NewBranchReferenceName("main")},
	})
	if err != nil {
		t.Fatalf("init repository: %v", err)
	}

	s := &GitServer{Root: root, repo: repo}
	backend := &cgi.Handler{
		Path: gitBin,
		Args: []string{"http-backend"},
		Env:  []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"},
	}
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		if cfg.auth != nil {
			user, password, ok := r.BasicAuth()
			if !ok || !cfg.auth(user, password) {
				w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		s.refs.RLock()
		defer s.refs.RUnlock()
		backend.ServeHTTP(w, r)
	}))
	if cfg.listen != "" {
		listener, err := net.Listen("tcp", cfg.listen)
		if err != nil {
			t.Fatalf("listen on %s: %v", cfg.listen, err)
		}
		_ = s.server.Listener.Close()
		s.server.Listener = listener
	}
	if cfg.tls {
		s.server.StartTLS()
	} else {
		s.server.Start()
	}
	t.Cleanup(s.server.Close)
	s.URL = s.server.URL + "/" + repoName
	return s
}

// Certificate returns the certificate of a server made with WithTLS, in PEM format.
func (s *GitServer) Certificate() []byte {
	cert := s.server.Certificate()
	if cert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// HostURL returns the URL of the repository for a client that reaches the server at host, which
// is the address of the machine that the test runs on as seen from the client.
func (s *GitServer) HostURL(host string) string {
	_, port, err := net.SplitHostPort(s.server.Listener.Addr().String())
	if err != nil {
		return s.URL
	}
	return "http://" + net.JoinHostPort(host, port) + "/" + repoName
}

func (s *GitServer) record(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.Method+" "+strings.TrimPrefix(r.URL.Path, "/"+repoName))
}

// Requests returns the requests that the server has handled so far, as "METHOD /path".
func (s *GitServer) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// CountRequests returns how many handled requests have exactly the given form.
func (s *GitServer) CountRequests(request string) int {
	n := 0
	for _, r := range s.Requests() {
		if r == request {
			n++
		}
	}
	return n
}

// Fetches returns how many times a client downloaded objects, as opposed to only listing
// references.
func (s *GitServer) Fetches() int {
	return s.CountRequests("POST /git-upload-pack")
}

// Commit writes the files and commits them to the current branch, and returns the commit SHA. A
// nil value deletes the file.
func (s *GitServer) Commit(t TB, message string, files map[string][]byte) string {
	t.Helper()
	wt, err := s.repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}

	for name, content := range files {
		if content == nil {
			if _, err := wt.Remove(name); err != nil {
				t.Fatalf("remove %s: %v", name, err)
			}
			continue
		}
		path := filepath.Join(wt.Filesystem.Root(), filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Add(name); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}
	return s.commit(t, wt, message)
}

// CommitSymlink commits a symbolic link at name that points to target.
func (s *GitServer) CommitSymlink(t TB, message, name, target string) string {
	t.Helper()
	wt, err := s.repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	path := filepath.Join(wt.Filesystem.Root(), filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(path)
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := wt.Add(name); err != nil {
		t.Fatalf("add %s: %v", name, err)
	}
	return s.commit(t, wt, message)
}

func (s *GitServer) commit(t TB, wt *git.Worktree, message string) string {
	t.Helper()
	s.refs.Lock()
	defer s.refs.Unlock()
	hash, err := wt.Commit(message, &git.CommitOptions{
		AllowEmptyCommits: true,
		Author:            &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	return hash.String()
}

// Tag makes a tag for the commit that the repository is at. An annotated tag is an object of its
// own that points to the commit, a lightweight tag is only a name for the commit.
func (s *GitServer) Tag(t TB, name string, annotated bool) {
	t.Helper()
	head, err := s.repo.Head()
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	s.refs.Lock()
	defer s.refs.Unlock()
	var opts *git.CreateTagOptions
	if annotated {
		opts = &git.CreateTagOptions{
			Tagger:  &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()},
			Message: "release " + name,
		}
	}
	if _, err := s.repo.CreateTag(name, head.Hash(), opts); err != nil {
		t.Fatalf("tag %s: %v", name, err)
	}
}

// Checkout switches to the branch, creating it from the current commit if needed.
func (s *GitServer) Checkout(t TB, branch string) {
	t.Helper()
	wt, err := s.repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	s.refs.Lock()
	defer s.refs.Unlock()
	ref := plumbing.NewBranchReferenceName(branch)
	err = wt.Checkout(&git.CheckoutOptions{Branch: ref})
	if err != nil {
		err = wt.Checkout(&git.CheckoutOptions{Branch: ref, Create: true})
	}
	if err != nil {
		t.Fatalf("checkout %s: %v", branch, err)
	}
}

// SetDefaultBranch points HEAD of the served repository at the branch.
func (s *GitServer) SetDefaultBranch(t TB, branch string) {
	t.Helper()
	s.refs.Lock()
	defer s.refs.Unlock()
	ref := plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName(branch))
	if err := s.repo.Storer.SetReference(ref); err != nil {
		t.Fatalf("set HEAD: %v", err)
	}
}
