package gitstore

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
)

const (
	// DefaultTimeout is the default limit for one fetch from a remote.
	DefaultTimeout = 30 * time.Second

	// DefaultMaxRepositoryBytes is the default limit for the size of a repository after decompression.
	DefaultMaxRepositoryBytes = 64 << 20
	// DefaultCacheBytes is the default limit for the memory that all the repositories that are kept take.
	DefaultCacheBytes = 128 << 20

	// maxListBytes is the limit for the answer of a server to the question what its branches are.
	// A repository with many thousands of references is a few megabytes.
	maxListBytes = 8 << 20
	// maxObjectBytes is the limit for the size of one object, or less when the repository may not be that large.
	maxObjectBytes = 16 << 20
	// maxObjects is the limit for the number of objects in a repository.
	maxObjects = 100_000
	// maxConcurrentClones is how many repositories are downloaded at the same time. Together with the limits
	// that makes the most memory that fetches take at any time something that can be sized.
	maxConcurrentClones = 2

	// idleTTL is how long a store that nobody asks for is kept.
	idleTTL = time.Hour
	// sweepEvery is how often the stores that are idle are looked for.
	sweepEvery = time.Minute
)

// ErrHostNotAllowed means the operator is configured to connect only to some hosts, and the repository
// is not on one of them.
var ErrHostNotAllowed = errors.New("host not allowed")

// Options configures a Manager. The zero value is usable.
type Options struct {
	// Timeout bounds one fetch from a remote, including the token exchange for a GitHub App and the
	// time that the connection to the server may last. It defaults to DefaultTimeout.
	Timeout time.Duration
	// MaxRepositoryBytes is the size that a repository may have after decompression. A server that sends more
	// is refused. It defaults to DefaultMaxRepositoryBytes.
	MaxRepositoryBytes int64
	// CacheBytes is the memory that the repositories that are kept may take together. The ones that were
	// used least are dropped to make room. It defaults to DefaultCacheBytes, and is never less than
	// MaxRepositoryBytes, as a repository that is allowed would not fit.
	CacheBytes int64
	// AllowedHosts, when it is not empty, are the only hosts that the operator connects to. A host is a
	// name such as "github.com", or "*.example.com" for the hosts below a domain.
	AllowedHosts []string
	// AllowInternalAddresses lets the operator connect to loopback and link-local addresses, which it
	// refuses by default. It is meant for tests.
	AllowInternalAddresses bool
	// HTTPClient is used for requests to the GitHub API. It defaults to a client with the limits
	// of the manager.
	HTTPClient *http.Client
	// Now returns the current time. It defaults to time.Now and is meant for tests.
	Now func() time.Time
}

// Manager fetches password stores and keeps the latest snapshot of each in memory. It is safe for
// concurrent use. Fetches of one store are serialized, fetches of different stores are not.
type Manager struct {
	opts Options
	// guard is the policy for downloading a repository, listGuard the one for asking what the
	// branches of a repository are, and for the exchange of a token of a GitHub App.
	guard     guard
	listGuard guard
	limits    limits
	apps      *appTokenSource
	// cloneSlots limits the number of repositories that are downloaded at the same time.
	cloneSlots chan struct{}

	mu        sync.Mutex
	entries   map[string]*entry
	lastSweep time.Time
}

// entry is the state kept for one store.
type entry struct {
	// lock serializes the fetches of the store. It is a channel, instead of a mutex, so that
	// a caller can stop waiting when its context ends.
	lock chan struct{}

	// bytes is the memory of the clone, and usedAt is when the store was last asked for, as Unix
	// nanoseconds. They can be read without the lock, to decide what to drop to make room.
	bytes  atomic.Int64
	usedAt atomic.Int64

	// The fields below are guarded by lock.

	fingerprint string
	clone       *clone
	// attemptedAt is when the remote was last contacted, err is how that ended.
	attemptedAt time.Time
	err         error
}

// clone is the result of a successful fetch.
type clone struct {
	storer storer.EncodedObjectStorer
	commit plumbing.Hash
	// tree is the root tree of the commit.
	tree plumbing.Hash
	// bytes is the memory that the objects take.
	bytes int64
}

// NewManager returns a Manager.
func NewManager(opts Options) *Manager {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxRepositoryBytes <= 0 {
		opts.MaxRepositoryBytes = DefaultMaxRepositoryBytes
	}
	if opts.CacheBytes <= 0 {
		opts.CacheBytes = DefaultCacheBytes
	}
	opts.CacheBytes = max(opts.CacheBytes, opts.MaxRepositoryBytes)
	if opts.Now == nil {
		opts.Now = time.Now
	}
	l := limits{
		// A packfile of data that does not compress is a little larger than what is in it.
		maxTransfer:   opts.MaxRepositoryBytes + 1<<20,
		maxObject:     min(maxObjectBytes, opts.MaxRepositoryBytes),
		maxRepository: opts.MaxRepositoryBytes,
		maxObjects:    maxObjects,
	}
	g := guard{timeout: opts.Timeout, maxBytes: l.maxTransfer, allowInternal: opts.AllowInternalAddresses}
	list := g
	list.maxBytes = min(maxListBytes, l.maxTransfer)
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{
			Transport: httpTransport,
			Timeout:   opts.Timeout,
			// The token exchange is a single request. A redirect would send the JWT, which can get a token
			// with all permissions of the App, to another place.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Manager{
		opts:       opts,
		guard:      g,
		listGuard:  list,
		limits:     l,
		apps:       newAppTokenSource(opts.HTTPClient, opts.Now, list),
		cloneSlots: make(chan struct{}, maxConcurrentClones),
		entries:    make(map[string]*entry),
	}
}

// Sync returns a snapshot of the store described by cfg. key identifies the store, a clone is
// cached per key and is replaced when cfg changes.
//
// The remote is only contacted when the last contact was at least maxAge ago, otherwise the
// result of that contact is returned again, which includes a failure. With a maxAge of zero the
// remote is always contacted. When the branch has not moved, the commit that is held is reused
// without downloading anything.
func (m *Manager) Sync(ctx context.Context, key string, cfg Config, maxAge time.Duration) (*Snapshot, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ep, err := cfg.endpoint()
	if err != nil {
		return nil, err
	}
	if err := m.checkHosts(cfg, ep); err != nil {
		return nil, err
	}

	e := m.entry(key)
	select {
	case e.lock <- struct{}{}:
		defer func() { <-e.lock }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	e.usedAt.Store(m.opts.Now().UnixNano())

	if fp := cfg.fingerprint(); e.fingerprint != fp {
		// Only the fields that the lock guards are reset. Callers that are waiting read e.lock
		// without holding it, so writing that field, even with the same value, would be a race.
		e.fingerprint = fp
		e.clone = nil
		e.bytes.Store(0)
		e.attemptedAt = time.Time{}
		e.err = nil
	}

	// A caller that waited for the lock finds the result of the caller before it here.
	if maxAge > 0 && e.clone != nil && e.err == nil && m.opts.Now().Sub(e.attemptedAt) < maxAge {
		return e.snapshot(cfg)
	}
	if maxAge > 0 && e.err != nil && m.opts.Now().Sub(e.attemptedAt) < maxAge {
		return nil, e.err
	}

	fetchCtx, cancel := context.WithTimeout(ctx, m.opts.Timeout)
	defer cancel()

	err = m.refresh(fetchCtx, e, cfg, ep)
	if err != nil && ctx.Err() != nil {
		// The caller gave up, which says nothing about the remote. The next caller tries again.
		return nil, err
	}
	// The error is kept for the cooldown, so it is made small first.
	err = shorten(err)
	e.attemptedAt = m.opts.Now()
	e.err = err
	if err != nil {
		return nil, err
	}
	return e.snapshot(cfg)
}

// Forget drops what is held for a store, for example because the store was deleted. A Sync that
// is running for the store finishes normally, its result is just not kept.
func (m *Manager) Forget(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
}

func (m *Manager) entry(key string) *entry {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.opts.Now()
	if now.Sub(m.lastSweep) >= sweepEvery {
		m.sweep(now)
		m.lastSweep = now
	}

	e, ok := m.entries[key]
	if !ok {
		e = &entry{lock: make(chan struct{}, 1)}
		e.usedAt.Store(now.UnixNano())
		m.entries[key] = e
	}
	return e
}

// sweep drops the stores that nobody has asked for in a long time. A store that is in use is asked
// for at least every few minutes, so these are stores that were deleted while a fetch was running,
// or that were changed to another key. It must be called with m.mu held.
func (m *Manager) sweep(now time.Time) {
	for key, e := range m.entries {
		if now.Sub(time.Unix(0, e.usedAt.Load())) > idleTTL {
			delete(m.entries, key)
		}
	}
}

// reserve makes room in the cache for a repository of size bytes, by dropping the repositories of the
// stores that were used least recently, and returns an error when that is not enough. The memory of
// the repository that the entry holds is not counted, it is replaced by the new one.
func (m *Manager) reserve(self *entry, size int64) error {
	if size > m.opts.CacheBytes {
		return fmt.Errorf("%w: the repository takes %d bytes of memory and the cache is %d bytes",
			ErrLimitExceeded, size, m.opts.CacheBytes)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var used int64
	var others []*entry
	for _, e := range m.entries {
		if e == self {
			continue
		}
		if b := e.bytes.Load(); b > 0 {
			used += b
			others = append(others, e)
		}
	}
	if used+size <= m.opts.CacheBytes {
		return nil
	}

	slices.SortFunc(others, func(a, b *entry) int { return cmp.Compare(a.usedAt.Load(), b.usedAt.Load()) })
	for _, e := range others {
		if used+size <= m.opts.CacheBytes {
			break
		}
		// A store that is being fetched is skipped, taking its lock would wait for it. The lock is only
		// ever taken here without waiting, so this cannot be part of a deadlock.
		select {
		case e.lock <- struct{}{}:
			used -= e.bytes.Load()
			e.clone = nil
			e.bytes.Store(0)
			<-e.lock
		default:
		}
	}
	if used+size > m.opts.CacheBytes {
		return fmt.Errorf("%w: there is no room in the cache of %d bytes for a repository of %d bytes",
			ErrLimitExceeded, m.opts.CacheBytes, size)
	}
	return nil
}

// checkHosts refuses a repository, or a GitHub API, on a host that the operator may not connect to.
func (m *Manager) checkHosts(cfg Config, ep *transport.Endpoint) error {
	if len(m.opts.AllowedHosts) == 0 {
		return nil
	}
	hosts := []string{ep.Host}
	if app := cfg.Auth.App; app != nil {
		if u, err := url.Parse(app.baseURL()); err == nil {
			hosts = append(hosts, u.Hostname())
		}
	}
	for _, host := range hosts {
		if !hostAllowed(host, m.opts.AllowedHosts) {
			return fmt.Errorf("%w: the operator may not connect to %q, it is limited to %s",
				ErrHostNotAllowed, host, strings.Join(m.opts.AllowedHosts, ", "))
		}
	}
	return nil
}

func hostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		switch {
		case a == host:
			return true
		case strings.HasPrefix(a, "*.") && strings.HasSuffix(host, a[1:]) && len(host) > len(a)-1:
			return true
		}
	}
	return false
}

// remote is a repository to connect to, with the policy for the connections to it.
type remote struct {
	url   string
	auth  transport.AuthMethod
	guard guard
	proxy transport.ProxyOptions
}

func newRemote(cfg Config, ep *transport.Endpoint, auth transport.AuthMethod, g guard) remote {
	return remote{url: cfg.URL, auth: auth, guard: g, proxy: g.proxyOptions(ep)}
}

// refresh makes e hold the latest commit of the branch.
func (m *Manager) refresh(ctx context.Context, e *entry, cfg Config, ep *transport.Endpoint) error {
	auth, err := m.authMethod(ctx, cfg, ep)
	if err != nil {
		return err
	}

	// The first question is which commit the branch is at, also when there is nothing to compare it
	// with. It costs little, and a server that does not answer is found out here, where no slot for a
	// download is held. Without it, a few servers that say nothing would keep the slots from the
	// stores that have something to download.
	ref := cfg.refName()
	head, err := newRemote(cfg, ep, auth, m.listGuard).commit(ctx, ref)
	if err != nil {
		return fmt.Errorf("list %s: %w", cfg.URL, explainError(err))
	}
	if e.clone != nil && head == e.clone.commit {
		return nil
	}

	c, err := m.clone(ctx, newRemote(cfg, ep, auth, m.guard), ref)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", cfg.URL, explainError(err))
	}
	if err := m.reserve(e, c.bytes); err != nil {
		return fmt.Errorf("fetch %s: %w", cfg.URL, err)
	}
	e.clone = c
	e.bytes.Store(c.bytes)
	return nil
}

// clone downloads the repository, when there is a free slot for it.
func (m *Manager) clone(ctx context.Context, r remote, name plumbing.ReferenceName) (*clone, error) {
	select {
	case m.cloneSlots <- struct{}{}:
		defer func() { <-m.cloneSlots }()
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for a free slot to download the repository: %w", ctx.Err())
	}
	return cloneRemote(ctx, r, name, m.limits)
}

// snapshot returns a view of the store inside the clone.
func (e *entry) snapshot(cfg Config) (*Snapshot, error) {
	root := e.clone.tree
	if p := cfg.cleanPath(); p != "" {
		tree, err := object.GetTree(e.clone.storer, root)
		if err != nil {
			return nil, err
		}
		sub, err := tree.Tree(p)
		if err != nil {
			return nil, fmt.Errorf("%w: %q", ErrPathNotFound, p)
		}
		root = sub.Hash
	}
	return &Snapshot{storer: e.clone.storer, commit: e.clone.commit, root: root}, nil
}

// refName converts the configured branch to a reference name. An empty name is the default
// branch of the remote.
func (c Config) refName() plumbing.ReferenceName {
	switch {
	case c.Branch == "":
		return ""
	case strings.HasPrefix(c.Branch, "refs/"):
		return plumbing.ReferenceName(c.Branch)
	default:
		return plumbing.NewBranchReferenceName(c.Branch)
	}
}

// commit returns the commit that the reference points to on the remote, which is the default
// branch if name is empty. It transfers the list of references, but no objects. An annotated tag
// points to a commit through an object of its own, the commit is the peeled reference.
func (r remote) commit(ctx context.Context, name plumbing.ReferenceName) (plumbing.Hash, error) {
	ctx = withGuard(ctx, r.guard)
	rem := git.NewRemote(memory.NewStorage(), &gitconfig.RemoteConfig{Name: git.DefaultRemoteName, URLs: []string{r.url}})
	refs, err := rem.ListContext(ctx, &git.ListOptions{Auth: r.auth, PeelingOption: git.AppendPeeled, ProxyOptions: r.proxy})
	if err != nil {
		return plumbing.ZeroHash, err
	}

	byName := make(map[plumbing.ReferenceName]*plumbing.Reference, len(refs))
	for _, ref := range refs {
		byName[ref.Name()] = ref
	}

	if name == "" {
		name = plumbing.HEAD
	}
	for range 8 {
		if peeled, ok := byName[plumbing.ReferenceName(string(name)+"^{}")]; ok && peeled.Type() == plumbing.HashReference {
			return peeled.Hash(), nil
		}
		ref, ok := byName[name]
		if !ok {
			return plumbing.ZeroHash, fmt.Errorf("%w: %s", plumbing.ErrReferenceNotFound, name)
		}
		if ref.Type() == plumbing.HashReference {
			return ref.Hash(), nil
		}
		name = ref.Target()
	}
	return plumbing.ZeroHash, errors.New("too many levels of symbolic references")
}

// cloneRemote fetches the latest commit of the reference, without its history, into memory.
func cloneRemote(ctx context.Context, r remote, name plumbing.ReferenceName, l limits) (*clone, error) {
	ctx = withGuard(ctx, r.guard)
	st := newLimitedStorage(l)
	repo, err := git.CloneContext(ctx, st, nil, &git.CloneOptions{
		URL:           r.url,
		Auth:          r.auth,
		ReferenceName: name,
		SingleBranch:  true,
		Depth:         1,
		Tags:          git.NoTags,
		ProxyOptions:  r.proxy,
	})
	if err != nil {
		return nil, err
	}

	head, err := repo.Head()
	if err != nil {
		return nil, err
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, err
	}
	return &clone{storer: st, commit: commit.Hash, tree: commit.TreeHash, bytes: st.stored}, nil
}
