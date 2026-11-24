package gitstore

import (
	"context"
	"errors"

	"github.com/sorend/passwordstore-operator/internal/printable"
)

// maxErrorLength bounds the message of an error that a fetch returns, in characters.
const maxErrorLength = 2048

// sentinels are the errors that callers tell apart. They are kept when an error is shortened.
var sentinels = []error{
	ErrInvalidConfig, ErrHostNotAllowed, ErrAddressNotAllowed, ErrLimitExceeded, ErrPathNotFound,
	context.DeadlineExceeded, context.Canceled,
}

// remoteError is an error of a fetch, with a message that was made fit to show. It stands in for the
// error of a library, which can hold the whole answer of a server, for as long as it is kept.
type remoteError struct {
	msg   string
	cause error
}

func (e *remoteError) Error() string { return e.msg }
func (e *remoteError) Unwrap() error { return e.cause }

// shorten returns err with a message that is shortened and has no control characters. What a
// server answers an error with can be as large as the server wants, and an error is kept in
// memory for some time. The errors in sentinels can still be found in the result with errors.Is.
func shorten(err error) error {
	if err == nil {
		return nil
	}
	out := &remoteError{msg: printable.String(err.Error(), maxErrorLength)}
	for _, s := range sentinels {
		if errors.Is(err, s) {
			out.cause = s
			break
		}
	}
	return out
}
