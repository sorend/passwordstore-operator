package printable_test

import (
	"strings"
	"testing"

	"github.com/sorend/passwordstore-operator/internal/printable"
)

func TestString(t *testing.T) {
	tests := map[string]struct {
		in    string
		limit int
		want  string
	}{
		"plain text is kept":      {"repository not found", 0, "repository not found"},
		"empty":                   {"", 10, ""},
		"unicode is kept":         {"pässwörd — 日本語", 0, "pässwörd — 日本語"},
		"line breaks and tabs":    {"one\ntwo\r\nthree\tfour", 0, "one two  three four"},
		"escape sequence":         {"ok\x1b[2J\x1b[31mred", 0, "ok[2J[31mred"},
		"nul and bell":            {"a\x00b\x07c", 0, "abc"},
		"delete":                  {"a\x7fb", 0, "ab"},
		"c1 control, a CSI":       {"a\u009bb", 0, "ab"},
		"right-to-left override":  {"a\u202eb", 0, "ab"},
		"isolate":                 {"a\u2066b\u2069c", 0, "abc"},
		"zero width space":        {"a\u200bb", 0, "ab"},
		"invalid utf-8 is marked": {"a\xffb", 0, "a\uFFFDb"},
		"exactly the limit":       {"abcde", 5, "abcde"},
		"one over the limit":      {"abcdef", 5, "abcde..."},
		"counted in characters":   {"ééééé", 3, "ééé..."},
		"the limit is of what is shown": {
			"\x1b\x1b\x1bab\x1b\x1bcd", 4, "abcd",
		},
		"negative is no limit": {"abcdef", -1, "abcdef"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := printable.String(tt.in, tt.limit); got != tt.want {
				t.Errorf("String(%q, %d) = %q, want %q", tt.in, tt.limit, got, tt.want)
			}
		})
	}
}

func TestStringOfHugeInput(t *testing.T) {
	// Text of a server can be as large as what the server sends, only the beginning is of interest.
	got := printable.String(strings.Repeat("x", 10<<20), 100)
	if len(got) != 103 || !strings.HasSuffix(got, "...") {
		t.Errorf("got %d bytes, want 100 characters and an ellipsis", len(got))
	}
}
