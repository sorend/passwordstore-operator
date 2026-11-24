package gitstore_test

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sorend/passwordstore-operator/internal/gitstore"
	"github.com/sorend/passwordstore-operator/internal/testutil"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *fakeClock { return &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func mustSync(t *testing.T, m *gitstore.Manager, key string, cfg gitstore.Config, maxAge time.Duration) *gitstore.Snapshot {
	t.Helper()
	snap, err := m.Sync(context.Background(), key, cfg, maxAge)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	return snap
}

func mustRead(t *testing.T, snap *gitstore.Snapshot, name string) string {
	t.Helper()
	data, err := snap.ReadFile(name)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", name, err)
	}
	return string(data)
}

func TestSyncClonesAndReadsFiles(t *testing.T) {
	server := testutil.NewGitServer(t)
	commit := server.Commit(t, "init", map[string][]byte{
		".gpg-id":                 []byte("KEYID\n"),
		"k8s/postgres/admin.gpg":  []byte("encrypted one"),
		"other/deeply/nested.gpg": []byte("encrypted two"),
	})

	snap := mustSync(t, newManager(gitstore.Options{}), "s", gitstore.Config{URL: server.URL}, 0)

	if snap.Revision() != commit {
		t.Errorf("Revision = %s, want %s", snap.Revision(), commit)
	}
	for name, want := range map[string]string{
		".gpg-id":                 "KEYID\n",
		"k8s/postgres/admin.gpg":  "encrypted one",
		"other/deeply/nested.gpg": "encrypted two",
	} {
		if got := mustRead(t, snap, name); got != want {
			t.Errorf("ReadFile(%s) = %q, want %q", name, got, want)
		}
	}

	for _, missing := range []string{"nope.gpg", "k8s/nope.gpg", "nope/dir/file.gpg", "k8s/postgres/admin.gpg/below-a-file"} {
		if _, err := snap.ReadFile(missing); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("ReadFile(%s) error = %v, want fs.ErrNotExist", missing, err)
		}
	}
	// A directory is not an entry.
	for _, dir := range []string{"k8s", "k8s/postgres", "other/deeply"} {
		if _, err := snap.ReadFile(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("ReadFile(%s) error = %v, want fs.ErrNotExist", dir, err)
		}
	}
}

func TestSyncStoreInSubdirectory(t *testing.T) {
	server := testutil.NewGitServer(t)
	server.Commit(t, "init", map[string][]byte{
		"README.md":         []byte("not part of the store"),
		"infra/pass/a.gpg":  []byte("in the store"),
		"infra/other/b.gpg": []byte("outside the store"),
	})
	m := newManager(gitstore.Options{})

	for _, p := range []string{"infra/pass", "/infra/pass/", "infra//pass"[:0] + "infra/pass"} {
		snap := mustSync(t, m, "s", gitstore.Config{URL: server.URL, Path: p}, 0)
		if got := mustRead(t, snap, "a.gpg"); got != "in the store" {
			t.Errorf("path %q: a.gpg = %q", p, got)
		}
		for _, outside := range []string{"README.md", "infra/other/b.gpg", "../README.md"} {
			if _, err := snap.ReadFile(outside); err == nil {
				t.Errorf("path %q: ReadFile(%s) must fail, it is outside of the store", p, outside)
			}
		}
	}

	t.Run("missing", func(t *testing.T) {
		_, err := m.Sync(context.Background(), "s", gitstore.Config{URL: server.URL, Path: "infra/nope"}, 0)
		if !errors.Is(err, gitstore.ErrPathNotFound) {
			t.Fatalf("err = %v, want ErrPathNotFound", err)
		}
	})
	t.Run("a file is not a directory", func(t *testing.T) {
		_, err := m.Sync(context.Background(), "s", gitstore.Config{URL: server.URL, Path: "README.md"}, 0)
		if !errors.Is(err, gitstore.ErrPathNotFound) {
			t.Fatalf("err = %v, want ErrPathNotFound", err)
		}
	})
}

func TestSyncBranches(t *testing.T) {
	server := testutil.NewGitServer(t)
	server.Commit(t, "on main", map[string][]byte{"which.gpg": []byte("main")})
	server.Checkout(t, "dev")
	server.Commit(t, "on dev", map[string][]byte{"which.gpg": []byte("dev")})
	server.Checkout(t, "main")
	m := newManager(gitstore.Options{})

	tests := map[string]struct {
		branch string
		want   string
	}{
		"default branch is main": {"", "main"},
		"explicit main":          {"main", "main"},
		"other branch":           {"dev", "dev"},
		"full reference":         {"refs/heads/dev", "dev"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			snap := mustSync(t, m, "branch-"+name, gitstore.Config{URL: server.URL, Branch: tt.branch}, 0)
			if got := mustRead(t, snap, "which.gpg"); got != tt.want {
				t.Errorf("branch %q reads %q, want %q", tt.branch, got, tt.want)
			}
		})
	}

	t.Run("follows the default branch of the remote", func(t *testing.T) {
		server.SetDefaultBranch(t, "dev")
		snap := mustSync(t, m, "default-follows", gitstore.Config{URL: server.URL}, 0)
		if got := mustRead(t, snap, "which.gpg"); got != "dev" {
			t.Errorf("reads %q from the default branch, want dev", got)
		}
	})

	t.Run("unknown branch", func(t *testing.T) {
		_, err := m.Sync(context.Background(), "unknown-branch", gitstore.Config{URL: server.URL, Branch: "nope"}, 0)
		if err == nil || !strings.Contains(err.Error(), "nope") {
			t.Fatalf("err = %v, want an error that names the branch", err)
		}
	})
}

func TestSyncPicksUpNewCommitsAndOldSnapshotsStay(t *testing.T) {
	server := testutil.NewGitServer(t)
	first := server.Commit(t, "one", map[string][]byte{"a.gpg": []byte("v1"), "gone.gpg": []byte("x")})
	m := newManager(gitstore.Options{})
	cfg := gitstore.Config{URL: server.URL}

	old := mustSync(t, m, "s", cfg, 0)
	second := server.Commit(t, "two", map[string][]byte{"a.gpg": []byte("v2"), "gone.gpg": nil, "new.gpg": []byte("n")})
	fresh := mustSync(t, m, "s", cfg, 0)

	if old.Revision() != first || fresh.Revision() != second {
		t.Fatalf("revisions = %s, %s; want %s, %s", old.Revision(), fresh.Revision(), first, second)
	}
	if got := mustRead(t, fresh, "a.gpg"); got != "v2" {
		t.Errorf("fresh a.gpg = %q, want v2", got)
	}
	if _, err := fresh.ReadFile("gone.gpg"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("deleted file: err = %v, want fs.ErrNotExist", err)
	}
	if got := mustRead(t, fresh, "new.gpg"); got != "n" {
		t.Errorf("new.gpg = %q", got)
	}

	// The snapshot that was taken earlier does not change, so a Secret that is being rendered
	// from it never sees a mix of two commits.
	if got := mustRead(t, old, "a.gpg"); got != "v1" {
		t.Errorf("old a.gpg = %q, want v1", got)
	}
	if got := mustRead(t, old, "gone.gpg"); got != "x" {
		t.Errorf("old gone.gpg = %q, want x", got)
	}
	if _, err := old.ReadFile("new.gpg"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("old snapshot must not see new.gpg: err = %v", err)
	}
}

func TestSyncDoesNotDownloadWhenNothingChanged(t *testing.T) {
	server := testutil.NewGitServer(t)
	server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("v1")})
	m := newManager(gitstore.Options{})
	cfg := gitstore.Config{URL: server.URL}

	mustSync(t, m, "s", cfg, 0)
	if server.Fetches() != 1 {
		t.Fatalf("first sync: %d fetches, want 1", server.Fetches())
	}
	for range 3 {
		mustSync(t, m, "s", cfg, 0)
	}
	if server.Fetches() != 1 {
		t.Errorf("unchanged repository: %d fetches, want it to stay at 1; requests: %v", server.Fetches(), server.Requests())
	}

	server.Commit(t, "change", map[string][]byte{"a.gpg": []byte("v2")})
	mustSync(t, m, "s", cfg, 0)
	if server.Fetches() != 2 {
		t.Errorf("after a commit: %d fetches, want 2", server.Fetches())
	}
}

func TestSyncCooldownAvoidsContactingTheRemote(t *testing.T) {
	server := testutil.NewGitServer(t)
	server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("v1")})
	clock := newClock()
	m := newManager(gitstore.Options{Now: clock.Now})
	cfg := gitstore.Config{URL: server.URL}
	const cooldown = time.Minute

	mustSync(t, m, "s", cfg, cooldown)
	contacts := len(server.Requests())

	// New content is not seen inside the cooldown, and nothing is requested.
	second := server.Commit(t, "change", map[string][]byte{"a.gpg": []byte("v2")})
	clock.Advance(30 * time.Second)
	snap := mustSync(t, m, "s", cfg, cooldown)
	if len(server.Requests()) != contacts {
		t.Errorf("inside the cooldown the remote was contacted: %v", server.Requests())
	}
	if got := mustRead(t, snap, "a.gpg"); got != "v1" {
		t.Errorf("inside the cooldown a.gpg = %q, want the cached v1", got)
	}

	// A caller that does not accept a cached result gets the new content straight away.
	if got := mustSync(t, m, "s", cfg, 0).Revision(); got != second {
		t.Errorf("forced sync: revision %s, want %s", got, second)
	}

	third := server.Commit(t, "change again", map[string][]byte{"a.gpg": []byte("v3")})
	clock.Advance(2 * time.Minute)
	if got := mustSync(t, m, "s", cfg, cooldown).Revision(); got != third {
		t.Errorf("after the cooldown: revision %s, want %s", got, third)
	}
}

func TestSyncRemembersFailuresDuringTheCooldown(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(broken.Close)
	count := func() int { mu.Lock(); defer mu.Unlock(); return hits }

	clock := newClock()
	m := newManager(gitstore.Options{Now: clock.Now})
	cfg := gitstore.Config{URL: broken.URL + "/repo.git"}
	const cooldown = time.Minute

	_, firstErr := m.Sync(context.Background(), "s", cfg, cooldown)
	if firstErr == nil {
		t.Fatal("expected an error")
	}
	hitsAfterFirst := count()

	// Callers inside the cooldown get the failure back without another attempt, so one broken
	// server cannot keep every worker busy with timeouts.
	for range 5 {
		_, err := m.Sync(context.Background(), "s", cfg, cooldown)
		if err == nil || err.Error() != firstErr.Error() {
			t.Fatalf("err = %v, want the first error %v", err, firstErr)
		}
	}
	if count() != hitsAfterFirst {
		t.Errorf("the remote was contacted again inside the cooldown (%d -> %d)", hitsAfterFirst, count())
	}

	// A forced sync, and one after the cooldown, do try again.
	_, _ = m.Sync(context.Background(), "s", cfg, 0)
	if count() <= hitsAfterFirst {
		t.Error("a forced sync must contact the remote")
	}
	before := count()
	clock.Advance(2 * time.Minute)
	_, _ = m.Sync(context.Background(), "s", cfg, cooldown)
	if count() <= before {
		t.Error("a sync after the cooldown must contact the remote")
	}
}

func TestSyncRecoversAfterFailure(t *testing.T) {
	server := testutil.NewGitServer(t, testutil.WithBasicAuth("user", "good"))
	server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("v1")})
	m := newManager(gitstore.Options{})

	bad := gitstore.Config{URL: server.URL, Auth: gitstore.Auth{Token: &gitstore.TokenAuth{Username: "user", Token: "wrong"}}}
	if _, err := m.Sync(context.Background(), "s", bad, 0); err == nil {
		t.Fatal("expected an error with a wrong token")
	}

	good := gitstore.Config{URL: server.URL, Auth: gitstore.Auth{Token: &gitstore.TokenAuth{Username: "user", Token: "good"}}}
	snap := mustSync(t, m, "s", good, time.Hour)
	if got := mustRead(t, snap, "a.gpg"); got != "v1" {
		t.Errorf("a.gpg = %q", got)
	}
}

func TestSyncCloneIsReplacedWhenTheConfigChanges(t *testing.T) {
	server := testutil.NewGitServer(t, testutil.WithBasicAuth("user", "pw"))
	server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("v1")})
	m := newManager(gitstore.Options{})

	cfg := gitstore.Config{URL: server.URL, Auth: gitstore.Auth{Token: &gitstore.TokenAuth{Username: "user", Token: "pw"}}}
	mustSync(t, m, "s", cfg, time.Hour)
	fetches := server.Fetches()

	// The same store with other credentials must not be served from the clone made with the
	// old ones: they may not be allowed to see the content.
	cfg.Auth.Token.Token = "revoked"
	if _, err := m.Sync(context.Background(), "s", cfg, time.Hour); err == nil {
		t.Fatal("a changed token must be checked, not served from the cache")
	}

	cfg.Auth.Token.Token = "pw"
	mustSync(t, m, "s", cfg, time.Hour)
	if server.Fetches() <= fetches {
		t.Error("expected a new clone after the configuration changed back and forth")
	}
}

func TestSyncStoresAreIndependent(t *testing.T) {
	a, b := testutil.NewGitServer(t), testutil.NewGitServer(t)
	a.Commit(t, "a", map[string][]byte{"which.gpg": []byte("a")})
	b.Commit(t, "b", map[string][]byte{"which.gpg": []byte("b")})
	m := newManager(gitstore.Options{})

	snapA := mustSync(t, m, "a", gitstore.Config{URL: a.URL}, time.Hour)
	snapB := mustSync(t, m, "b", gitstore.Config{URL: b.URL}, time.Hour)
	if mustRead(t, snapA, "which.gpg") != "a" || mustRead(t, snapB, "which.gpg") != "b" {
		t.Error("stores must not share state")
	}
}

func TestForgetDropsTheClone(t *testing.T) {
	server := testutil.NewGitServer(t)
	server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("v1")})
	m := newManager(gitstore.Options{})
	cfg := gitstore.Config{URL: server.URL}

	snap := mustSync(t, m, "s", cfg, 0)
	m.Forget("s")
	m.Forget("never-existed")

	// What was handed out stays usable, and a new Sync starts from scratch.
	if got := mustRead(t, snap, "a.gpg"); got != "v1" {
		t.Errorf("snapshot after Forget: %q", got)
	}
	mustSync(t, m, "s", cfg, time.Hour)
	if server.Fetches() != 2 {
		t.Errorf("%d fetches, want a second one after Forget", server.Fetches())
	}
}

func TestSyncEmptyRepository(t *testing.T) {
	server := testutil.NewGitServer(t)
	_, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", gitstore.Config{URL: server.URL}, 0)
	if err == nil {
		t.Fatal("expected an error for a repository without commits")
	}
}

func TestSyncUnknownRepository(t *testing.T) {
	server := testutil.NewGitServer(t)
	server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("v1")})
	_, err := newManager(gitstore.Options{}).Sync(context.Background(), "s",
		gitstore.Config{URL: strings.TrimSuffix(server.URL, "/store") + "/missing"}, 0)
	if err == nil {
		t.Fatal("expected an error for a repository that does not exist")
	}
}

func TestSyncRejectsInvalidConfigWithoutNetwork(t *testing.T) {
	_, err := newManager(gitstore.Options{}).Sync(context.Background(), "s", gitstore.Config{URL: "file:///etc"}, 0)
	if !errors.Is(err, gitstore.ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
}

func TestSyncTimesOut(t *testing.T) {
	release := make(chan struct{})
	hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); hanging.Close() })

	m := newManager(gitstore.Options{Timeout: 300 * time.Millisecond})
	start := time.Now()
	_, err := m.Sync(context.Background(), "s", gitstore.Config{URL: hanging.URL + "/repo.git"}, 0)
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Sync took %s, the timeout is not applied", elapsed)
	}
}

func TestSyncStopsWaitingWhenTheContextEnds(t *testing.T) {
	release := make(chan struct{})
	hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); hanging.Close() })

	m := newManager(gitstore.Options{Timeout: 10 * time.Second})
	cfg := gitstore.Config{URL: hanging.URL + "/repo.git"}

	// The first caller occupies the store.
	started := make(chan struct{})
	go func() {
		close(started)
		_, _ = m.Sync(context.Background(), "s", cfg, 0)
	}()
	<-started
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	begin := time.Now()
	_, err := m.Sync(ctx, "s", cfg, 0)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if time.Since(begin) > 3*time.Second {
		t.Error("a waiting caller must give up when its context ends")
	}
}

func TestSyncConcurrently(t *testing.T) {
	server := testutil.NewGitServer(t)
	server.Commit(t, "init", map[string][]byte{"a.gpg": []byte("v1"), "dir/b.gpg": []byte("v1b")})
	m := newManager(gitstore.Options{})
	cfg := gitstore.Config{URL: server.URL}

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := range 16 {
		wg.Go(func() {
			for j := range 4 {
				// Half of the callers share a cooldown, half force a check.
				maxAge := time.Duration(0)
				if i%2 == 0 {
					maxAge = time.Minute
				}
				snap, err := m.Sync(context.Background(), "s", cfg, maxAge)
				if err != nil {
					errs <- err
					return
				}
				for _, name := range []string{"a.gpg", "dir/b.gpg"} {
					if _, err := snap.ReadFile(name); err != nil {
						errs <- err
						return
					}
				}
				if j == 2 && i == 0 {
					server.Commit(t, "concurrent", map[string][]byte{"a.gpg": []byte("v2")})
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestSyncRejectsFilesOverTheLimit(t *testing.T) {
	server := testutil.NewGitServer(t)
	server.Commit(t, "init", map[string][]byte{
		"ok.gpg":  make([]byte, gitstore.MaxFileSize),
		"big.gpg": make([]byte, gitstore.MaxFileSize+1),
	})
	snap := mustSync(t, newManager(gitstore.Options{}), "s", gitstore.Config{URL: server.URL}, 0)

	if data, err := snap.ReadFile("ok.gpg"); err != nil || len(data) != gitstore.MaxFileSize {
		t.Errorf("a file at the limit: %d bytes, %v", len(data), err)
	}
	if _, err := snap.ReadFile("big.gpg"); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("a file over the limit: err = %v", err)
	}
}
