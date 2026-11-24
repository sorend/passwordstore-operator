package testutil

// TB is the part of testing.TB that the helpers use. It is implemented by *testing.T and by
// GinkgoT(), so the helpers can be used from both kinds of tests.
type TB interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Skip(args ...any)
	Cleanup(func())
	TempDir() string
}
