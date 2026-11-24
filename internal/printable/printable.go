// Package printable makes text that comes from somewhere else fit to be shown in a status, an event
// or a log line.
//
// What a Git server, or any other server, answers with ends up in resources that more people can
// read than the credentials, and in the terminal of whoever runs "kubectl describe". Text that is
// not cleaned can hold escape sequences, which move the cursor and overwrite what was printed
// before, and characters that reorder what is shown.
package printable

import (
	"strings"
	"unicode"
)

// ellipsis is added to text that was cut short.
const ellipsis = "..."

// String returns s with line breaks and tabs replaced by a space and the other control and
// formatting characters removed, shortened to at most limit characters, followed by "..." when
// something was left out. A limit of zero or less does not shorten.
func String(s string, limit int) string {
	var b strings.Builder
	b.Grow(min(len(s), max(limit, 0)+len(ellipsis)))

	n := 0
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			r = ' '
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			continue
		}
		if limit > 0 && n >= limit {
			b.WriteString(ellipsis)
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
