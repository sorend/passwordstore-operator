package gitstore_test

import "github.com/sorend/passwordstore-operator/internal/gitstore"

// newManager returns a Manager for the tests that talk to the servers of testutil, which listen on
// the loopback interface. A Manager made with gitstore.NewManager refuses those addresses, as it
// does in production, and the tests of that policy use it.
func newManager(opts gitstore.Options) *gitstore.Manager {
	opts.AllowInternalAddresses = true
	return gitstore.NewManager(opts)
}
