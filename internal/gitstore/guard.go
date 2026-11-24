package gitstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"golang.org/x/net/proxy"
)

var (
	// ErrLimitExceeded means a Git server sent more than the operator accepts.
	ErrLimitExceeded = errors.New("limit exceeded")
	// ErrAddressNotAllowed means the operator does not connect to the address of a Git server.
	ErrAddressNotAllowed = errors.New("address not allowed")
)

// guard is the policy for the connections of one fetch. It decides which addresses the operator
// connects to, how long a connection may last and how much a server may send. It is carried by the
// context of the fetch to the HTTP transport, and in the URL of a "proxy" to the SSH dialer, because
// those are the hooks that go-git offers to get at the connections.
//
// Without it a Git server, which is chosen by whoever can create a PasswordStore, could keep a
// worker busy for ever by saying nothing after the handshake, make the operator hold gigabytes
// in memory with a response that is small on the wire, or have it connect to the metadata service
// of the cloud and show what it answers in the status.
type guard struct {
	// timeout is the time that a connection may last: it is set on the connection as a deadline, which
	// covers the SSH handshake that go-git and x/crypto leave without a limit.
	timeout time.Duration
	// maxBytes is how much a server may send in one connection or one HTTP response.
	maxBytes int64
	// allowInternal lets the operator connect to loopback and link-local addresses.
	allowInternal bool
}

type guardKey struct{}

func withGuard(ctx context.Context, g guard) context.Context {
	return context.WithValue(ctx, guardKey{}, g)
}

// guardFrom returns the guard of a fetch. The default is the strictest one that works.
func guardFrom(ctx context.Context) guard {
	if g, ok := ctx.Value(guardKey{}).(guard); ok {
		return g
	}
	return guard{timeout: DefaultTimeout, maxBytes: DefaultMaxRepositoryBytes}
}

// maxErrorBodyBytes is how much of the body of an error response is read. It ends up in a message,
// and no Git server has a reason to send more than a sentence.
const maxErrorBodyBytes = 64 << 10

// awsIPv6MetadataService is the metadata service of EC2 on IPv6. It is not link-local.
var awsIPv6MetadataService = netip.MustParseAddr("fd00:ec2::254")

// checkAddress refuses the addresses that no Git server is at, and that a cloud answers a pod on with
// credentials: loopback, link-local (169.254.169.254 is the metadata service of the clouds), unspecified,
// multicast. The addresses of the cluster and of private networks are allowed, as that is where
// in-cluster Git servers are.
func (g guard) checkAddress(ip netip.Addr) error {
	ip = ip.Unmap().WithZone("")
	if g.allowInternal {
		return nil
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip == awsIPv6MetadataService {
		return fmt.Errorf("%w: %s is a loopback, link-local or otherwise internal address", ErrAddressNotAllowed, ip)
	}
	return nil
}

// control is called by the dialer for every connection, with the address that was resolved, so it
// cannot be avoided with a host name that resolves to an internal address.
func (g guard) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %q is not an IP address", ErrAddressNotAllowed, host)
	}
	return g.checkAddress(ip)
}

func (g guard) dialer() *net.Dialer {
	return &net.Dialer{Timeout: g.timeout, KeepAlive: 30 * time.Second, Control: g.control}
}

// limitError is what is returned when a server sends more than maxBytes.
func (g guard) limitError() error {
	return fmt.Errorf("%w: the server sent more than %d bytes", ErrLimitExceeded, g.maxBytes)
}

// guardedTransport is the HTTP transport of every fetch from an http(s) repository and of the GitHub
// API. It takes its policy from the context of each request, so one instance is enough.
type guardedTransport struct {
	mu         sync.Mutex
	transports map[transportKey]*http.Transport
}

// transportKey is what makes one transport differ from another. The limit on the size of a response is
// applied to each response, so it is not part of it, and the requests that ask for the references and
// the ones that download share their connections.
type transportKey struct {
	timeout       time.Duration
	allowInternal bool
}

func newGuardedTransport() *guardedTransport {
	return &guardedTransport{transports: make(map[transportKey]*http.Transport)}
}

func (t *guardedTransport) transport(g guard) *http.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := transportKey{timeout: g.timeout, allowInternal: g.allowInternal}
	tr, ok := t.transports[key]
	if !ok {
		tr = &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			DialContext:            g.dialer().DialContext,
			ForceAttemptHTTP2:      true,
			MaxIdleConns:           10,
			IdleConnTimeout:        90 * time.Second,
			TLSHandshakeTimeout:    10 * time.Second,
			ExpectContinueTimeout:  time.Second,
			ResponseHeaderTimeout:  g.timeout,
			MaxResponseHeaderBytes: 64 << 10,
		}
		t.transports[key] = tr
	}
	return tr
}

// RoundTrip limits the body of the response. go-git reads the body of an error response entirely
// into memory and into the error, and a ref advertisement or a pack has no size that it checks.
// The body that is limited is the one that is decompressed, so a compressed response is limited too.
func (t *guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	g := guardFrom(req.Context())
	resp, err := t.transport(g).RoundTrip(req)
	if err != nil {
		return nil, err
	}
	limit := g.maxBytes
	if resp.StatusCode >= http.StatusMultipleChoices {
		limit = min(limit, maxErrorBodyBytes)
	}
	resp.Body = &cappedBody{ReadCloser: resp.Body, remaining: limit, g: guard{timeout: g.timeout, maxBytes: limit}}
	return resp, nil
}

// httpTransport is shared by the fetches over http(s) and the requests to the GitHub API.
var httpTransport = newGuardedTransport()

func init() {
	// go-git has one client per scheme. The one it has takes the system defaults of net/http.
	c := githttp.NewClient(&http.Client{Transport: httpTransport})
	client.InstallProtocol("http", c)
	client.InstallProtocol("https", c)
	// The operator speaks http, https and ssh. Validate refuses other URLs, and these are taken away as
	// well: the file protocol runs a program on the machine of the operator, and git:// is neither
	// authenticated nor encrypted.
	client.InstallProtocol("file", nil)
	client.InstallProtocol("git", nil)

	proxy.RegisterDialerType(guardScheme, newGuardDialer)
}

type cappedBody struct {
	io.ReadCloser
	remaining int64
	g         guard
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		// A body that ends exactly at the limit is fine, only more is not.
		var probe [1]byte
		n, err := b.ReadCloser.Read(probe[:])
		if n > 0 {
			return 0, b.g.limitError()
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}

// guardScheme is the URL scheme under which the guard dialer is registered with x/net/proxy. go-git
// dials SSH connections through the "proxy" of an endpoint, which is the one place where it lets a
// caller get at the connection: it does not bound the handshake, and does not take a context.
const guardScheme = "passwordstore-guard"

// proxyOptions returns what makes go-git dial an ssh endpoint through the guard, and nothing for
// other endpoints, which are guarded through their transport.
func (g guard) proxyOptions(ep *transport.Endpoint) transport.ProxyOptions {
	if ep.Protocol != schemeSSH {
		return transport.ProxyOptions{}
	}
	q := url.Values{}
	q.Set("timeout", g.timeout.String())
	q.Set("max", strconv.FormatInt(g.maxBytes, 10))
	q.Set("internal", strconv.FormatBool(g.allowInternal))
	return transport.ProxyOptions{URL: guardScheme + "://guard?" + q.Encode()}
}

func newGuardDialer(u *url.URL, _ proxy.Dialer) (proxy.Dialer, error) {
	q := u.Query()
	timeout, err := time.ParseDuration(q.Get("timeout"))
	if err != nil || timeout <= 0 {
		return nil, fmt.Errorf("guard: invalid timeout in %q", u.Redacted())
	}
	maxBytes, err := strconv.ParseInt(q.Get("max"), 10, 64)
	if err != nil || maxBytes <= 0 {
		return nil, fmt.Errorf("guard: invalid size in %q", u.Redacted())
	}
	return &guardDialer{g: guard{timeout: timeout, maxBytes: maxBytes, allowInternal: q.Get("internal") == "true"}}, nil
}

// guardDialer connects to an SSH server. The connection has a deadline for everything that is done on
// it, and an upper limit to what it reads. An ALL_PROXY in the environment is still used, with the
// guard applying to the connections that are made.
type guardDialer struct{ g guard }

func (d *guardDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *guardDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	deadline := time.Now().Add(d.g.timeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	forward := proxy.FromEnvironmentUsing(d.g.dialer())
	var (
		conn net.Conn
		err  error
	)
	if cd, ok := forward.(proxy.ContextDialer); ok {
		conn, err = cd.DialContext(ctx, network, addr)
	} else {
		conn, err = forward.Dial(network, addr)
	}
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &cappedConn{Conn: conn, remaining: d.g.maxBytes, g: d.g}, nil
}

type cappedConn struct {
	net.Conn
	remaining int64
	g         guard
}

func (c *cappedConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, c.g.limitError()
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= int64(n)
	return n, err
}
