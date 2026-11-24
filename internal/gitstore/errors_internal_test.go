package gitstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestShorten(t *testing.T) {
	t.Run("nothing stays nothing", func(t *testing.T) {
		if shorten(nil) != nil {
			t.Error("shorten(nil) is not nil")
		}
	})

	t.Run("the errors that callers tell apart are still found", func(t *testing.T) {
		for _, sentinel := range sentinels {
			wrapped := fmt.Errorf("fetch https://example.com/x.git: %w", fmt.Errorf("deeper: %w", sentinel))
			got := shorten(wrapped)
			if !errors.Is(got, sentinel) {
				t.Errorf("errors.Is(shorten(%v), %v) = false", wrapped, sentinel)
			}
			if got.Error() != wrapped.Error() {
				t.Errorf("a short message was changed: %q", got.Error())
			}
		}
	})

	t.Run("another error is only its message", func(t *testing.T) {
		inner := errors.New("a library said so")
		got := shorten(fmt.Errorf("fetch: %w", inner))
		if errors.Is(got, inner) {
			t.Error("the error of the library is kept, and with it whatever it holds")
		}
		if got.Error() != "fetch: a library said so" {
			t.Errorf("message = %q", got.Error())
		}
	})

	t.Run("an answer of a server is shortened and cleaned", func(t *testing.T) {
		answer := "\x1b[2Jthe answer " + strings.Repeat("of a server that does not stop ", 100000)
		got := shorten(fmt.Errorf("authentication required: %s", answer))
		if len(got.Error()) > maxErrorLength+10 {
			t.Errorf("the message is %d bytes long", len(got.Error()))
		}
		if strings.ContainsRune(got.Error(), 0x1b) {
			t.Error("the message has an escape character in it")
		}
		if !strings.HasSuffix(got.Error(), "...") {
			t.Error("the message does not show that it was cut short")
		}
	})

	t.Run("a deadline is still a deadline", func(t *testing.T) {
		if !errors.Is(shorten(fmt.Errorf("list: %w", context.DeadlineExceeded)), context.DeadlineExceeded) {
			t.Error("the deadline was lost")
		}
	})
}
