package gitstore

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
)

func TestCheckAddress(t *testing.T) {
	strict, lax := guard{}, guard{allowInternal: true}

	// What no Git server is at, and what the clouds answer a pod on with credentials.
	refused := []string{
		"127.0.0.1", "127.255.255.254", "::1",
		"169.254.169.254", "169.254.0.1", "fe80::1", "fe80::1%eth0",
		"fd00:ec2::254",
		"0.0.0.0", "::",
		"224.0.0.1", "ff02::1",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", // an IPv4 address in the form of an IPv6 address
	}
	// The addresses of the cluster, of private networks and of the internet are where Git servers are.
	allowed := []string{
		"10.0.0.1", "10.43.0.10", "172.16.5.4", "192.168.1.1",
		"100.64.0.1", "100.101.102.103", // the range of carrier-grade NAT, which Tailscale uses
		"8.8.8.8", "140.82.112.3",
		"2001:db8::1", "fc00::1", "fd12:3456::1", "::ffff:10.0.0.1",
	}

	for _, s := range refused {
		ip := netip.MustParseAddr(s)
		if err := strict.checkAddress(ip); !errors.Is(err, ErrAddressNotAllowed) {
			t.Errorf("%s: err = %v, want ErrAddressNotAllowed", s, err)
		}
		if err := lax.checkAddress(ip); err != nil {
			t.Errorf("%s: the policy for tests refused it: %v", s, err)
		}
	}
	for _, s := range allowed {
		if err := strict.checkAddress(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s: err = %v, want it allowed", s, err)
		}
	}
}

func TestControlSeesTheAddressOfTheConnection(t *testing.T) {
	// What the dialer hands to Control is an IP address and a port, also for IPv6 and with a zone.
	g := guard{}
	for address, wantRefused := range map[string]bool{
		"127.0.0.1:22":         true,
		"[::1]:443":            true,
		"[fe80::1%eth0]:22":    true,
		"169.254.169.254:80":   true,
		"10.1.2.3:22":          false,
		"[2001:db8::1]:443":    false,
		"140.82.112.3:443":     false,
		"[::ffff:127.0.0.1]:1": true,
	} {
		err := g.control("tcp", address, nil)
		if wantRefused != (err != nil) {
			t.Errorf("control(%s) = %v, refused should be %v", address, err, wantRefused)
		}
	}

	// A name is not an address. The dialer resolves names first, so this is not expected, and it is
	// refused, as an address that cannot be checked is not one to connect to.
	if err := g.control("tcp", "example.com:443", nil); !errors.Is(err, ErrAddressNotAllowed) {
		t.Errorf("a host name: err = %v, want ErrAddressNotAllowed", err)
	}
	if err := g.control("tcp", "no-port", nil); err == nil {
		t.Error("an address without a port must be refused")
	}
}

func TestHostAllowed(t *testing.T) {
	list := []string{"github.com", "*.example.com", " GitLab.Example.org ", "10.0.0.5"}
	tests := map[string]bool{
		"github.com":           true,
		"GitHub.com":           true,
		"github.com.":          true, // the root of the name system, as it is written in a fully qualified name
		"api.github.com":       false,
		"evilgithub.com":       false,
		"github.com.evil.test": false,
		"git.example.com":      true,
		"a.b.example.com":      true,
		"example.com":          false, // a wildcard is for what is below a domain
		"notexample.com":       false,
		"gitlab.example.org":   true,
		"10.0.0.5":             true,
		"10.0.0.50":            false,
		"":                     false,
	}
	for host, want := range tests {
		if got := hostAllowed(host, list); got != want {
			t.Errorf("hostAllowed(%q) = %v, want %v", host, got, want)
		}
	}
	if hostAllowed("github.com", nil) {
		t.Error("an empty list allows nothing, the caller treats an empty list as no restriction")
	}
}

func TestOnlyHTTPAndSSHAreSpoken(t *testing.T) {
	// Validate refuses the other schemes before anything is made of them. This is what is left if it
	// were bypassed: go-git has no client for them, in particular none for file://, which would run a
	// program on the machine of the operator.
	for url, wantClient := range map[string]bool{
		"https://example.com/org/repo.git":   true,
		"http://example.com/org/repo.git":    true,
		"ssh://git@example.com/org/repo.git": true,
		"git@example.com:org/repo.git":       true,
		"git://example.com/org/repo.git":     false,
		"file:///var/run/secrets/repo.git":   false,
		"/var/run/secrets/repo.git":          false,
	} {
		ep, err := transport.NewEndpoint(url)
		if err != nil {
			t.Fatalf("%s: %v", url, err)
		}
		_, err = client.NewClient(ep)
		if wantClient != (err == nil) {
			t.Errorf("%s: client error = %v, a client should exist: %v", url, err, wantClient)
		}
	}
}

func TestTransportsAreSharedByTheLimitsOfSizes(t *testing.T) {
	// The size that a response may have is checked for each response, so it does not need a transport
	// of its own: the requests for the references and for the download use the same connections.
	transports := newGuardedTransport()
	list := guard{timeout: time.Second, maxBytes: 8 << 20}
	download := guard{timeout: time.Second, maxBytes: 65 << 20}
	if transports.transport(list) != transports.transport(download) {
		t.Error("the transports of two limits of size differ")
	}
	if transports.transport(list) == transports.transport(guard{timeout: time.Second, maxBytes: 8 << 20, allowInternal: true}) {
		t.Error("a transport that may connect to internal addresses is shared with one that may not")
	}
	if transports.transport(list) == transports.transport(guard{timeout: 2 * time.Second, maxBytes: 8 << 20}) {
		t.Error("transports with other timeouts are shared")
	}
}
