package entry_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sorend/passwordstore-operator/internal/entry"
)

func TestParse(t *testing.T) {
	tests := []struct {
		value string
		want  entry.Ref
	}{
		{"k8s/postgres.db.svc/admin-user", entry.Ref{Path: "k8s/postgres.db.svc/admin-user"}},
		{"simple", entry.Ref{Path: "simple"}},
		{"/k8s/leading-slash", entry.Ref{Path: "k8s/leading-slash"}},
		{"//k8s/two-leading-slashes", entry.Ref{Path: "k8s/two-leading-slashes"}},
		{"with spaces/and unicode-ü", entry.Ref{Path: "with spaces/and unicode-ü"}},
		{"dots.in.names/a..b", entry.Ref{Path: "dots.in.names/a..b"}},
		{"k8s/db#1", entry.Ref{Path: "k8s/db", Selector: entry.Selector{Kind: entry.SelectLine, Line: 1}}},
		{"k8s/db#12", entry.Ref{Path: "k8s/db", Selector: entry.Selector{Kind: entry.SelectLine, Line: 12}}},
		{"k8s/db#username", entry.Ref{Path: "k8s/db", Selector: entry.Selector{Kind: entry.SelectField, Field: "username"}}},
		{"k8s/db#User Name", entry.Ref{Path: "k8s/db", Selector: entry.Selector{Kind: entry.SelectField, Field: "User Name"}}},
		{"k8s/db# padded ", entry.Ref{Path: "k8s/db", Selector: entry.Selector{Kind: entry.SelectField, Field: "padded"}}},
		// A "#" followed by "/" cannot be a selector, so it is part of the path.
		{"k8s/c#sharp/pass", entry.Ref{Path: "k8s/c#sharp/pass"}},
		{"k8s/c#sharp/pass#2", entry.Ref{Path: "k8s/c#sharp/pass", Selector: entry.Selector{Kind: entry.SelectLine, Line: 2}}},
		{"a#b#c", entry.Ref{Path: "a#b", Selector: entry.Selector{Kind: entry.SelectField, Field: "c"}}},
		{"x.gpg", entry.Ref{Path: "x.gpg"}},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got, err := entry.Parse(tt.value)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.value, err)
			}
			if got != tt.want {
				t.Errorf("Parse(%q) = %+v, want %+v", tt.value, got, tt.want)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	tests := map[string]string{
		"empty":                   "",
		"only a slash":            "/",
		"only a selector":         "#1",
		"parent directory":        "../secret",
		"parent in the middle":    "k8s/../../etc/passwd",
		"parent at the end":       "k8s/..",
		"current directory":       "k8s/./db",
		"double slash":            "k8s//db",
		"trailing slash":          "k8s/db/",
		"backslash":               `k8s\db`,
		"nul byte":                "k8s/db\x00",
		"newline in path":         "k8s/db\nx",
		"tab in path":             "k8s/\tdb",
		"empty selector":          "k8s/db#",
		"blank selector":          "k8s/db#   ",
		"line zero":               "k8s/db#0",
		"line zero padded":        "k8s/db#00",
		"line number too large":   "k8s/db#99999999999999999999",
		"selector with newline":   "k8s/db#user\nname",
		"a colon in a field name": "k8s/db#a:b",
		"selector only slashes":   "///#1",
		"path too long":           strings.Repeat("a/", 600),
		"traversal after prefix":  "/../x",
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			ref, err := entry.Parse(value)
			if err == nil {
				t.Fatalf("Parse(%q) = %+v, expected an error", value, ref)
			}
			if !errors.Is(err, entry.ErrInvalid) {
				t.Errorf("Parse(%q) error %v is not ErrInvalid", value, err)
			}
		})
	}
}

func TestFiles(t *testing.T) {
	tests := []struct {
		value string
		want  []string
	}{
		{"k8s/db/admin", []string{"k8s/db/admin.gpg"}},
		{"k8s/db/admin.gpg", []string{"k8s/db/admin.gpg.gpg", "k8s/db/admin.gpg"}},
		{".gpg", []string{".gpg.gpg"}},
	}
	for _, tt := range tests {
		ref, err := entry.Parse(tt.value)
		if err != nil {
			t.Fatal(err)
		}
		got := ref.Files()
		if strings.Join(got, ",") != strings.Join(tt.want, ",") {
			t.Errorf("Files(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestRefString(t *testing.T) {
	for _, value := range []string{"a/b", "a/b#3", "a/b#username", "a#b/c"} {
		ref, err := entry.Parse(value)
		if err != nil {
			t.Fatal(err)
		}
		if got := ref.String(); got != value {
			t.Errorf("String() = %q, want %q", got, value)
		}
	}
}

func TestSelectWholeEntry(t *testing.T) {
	const pem = "-----BEGIN OPENSSH PRIVATE " + "KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE " + "KEY-----\n"

	tests := map[string]struct{ content, want string }{
		"single line with newline": {"hunter2\n", "hunter2"},
		"single line with CRLF":    {"hunter2\r\n", "hunter2"},
		"single line, no newline":  {"hunter2", "hunter2"},
		"empty":                    {"", ""},
		"only a newline":           {"\n", ""},
		"lone CR is kept":          {"hunter2\r", "hunter2\r"},
		"trailing spaces are kept": {"hunter2 \n", "hunter2 "},
		"leading spaces are kept":  {"  hunter2\n", "  hunter2"},
		"two newlines is multi":    {"hunter2\n\n", "hunter2\n\n"},
		"multi line is verbatim":   {"hunter2\nusername: bob\n", "hunter2\nusername: bob\n"},
		"multi line, no final":     {"a\nb", "a\nb"},
		// An OpenSSH private key must keep its final newline or ssh refuses to load it.
		"pem keeps final newline": {pem, pem},
		"unicode":                 {"pässwörd\n", "pässwörd"},
	}
	ref, _ := entry.Parse("any")
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ref.Select([]byte(tt.content))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("Select(%q) = %q, want %q", tt.content, got, tt.want)
			}
		})
	}
}

func TestSelectDoesNotModifyInput(t *testing.T) {
	ref, _ := entry.Parse("any")
	in := []byte("secret\n")
	if _, err := ref.Select(in); err != nil {
		t.Fatal(err)
	}
	if string(in) != "secret\n" {
		t.Errorf("input was modified: %q", in)
	}
}

func TestSelectLine(t *testing.T) {
	const content = "hunter2\nusername: bob\r\n\nlast line without newline"

	tests := []struct {
		selector string
		want     string
		wantErr  bool
	}{
		{"1", "hunter2", false},
		{"2", "username: bob", false}, // CRLF is removed
		{"3", "", false},              // an empty line in the middle is a line
		{"4", "last line without newline", false},
		{"5", "", true},
		{"100", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			ref, err := entry.Parse("p#" + tt.selector)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ref.Select([]byte(content))
			if tt.wantErr {
				if !errors.Is(err, entry.ErrSelectorNotFound) {
					t.Fatalf("err = %v, want ErrSelectorNotFound", err)
				}
				return
			}
			if err != nil || string(got) != tt.want {
				t.Errorf("Select = %q, %v; want %q", got, err, tt.want)
			}
		})
	}

	t.Run("a final newline does not add a line", func(t *testing.T) {
		ref, _ := entry.Parse("p#2")
		if _, err := ref.Select([]byte("only\n")); !errors.Is(err, entry.ErrSelectorNotFound) {
			t.Fatalf("err = %v, want ErrSelectorNotFound", err)
		}
	})

	t.Run("empty entry has no lines", func(t *testing.T) {
		ref, _ := entry.Parse("p#1")
		if _, err := ref.Select(nil); !errors.Is(err, entry.ErrSelectorNotFound) {
			t.Fatalf("err = %v, want ErrSelectorNotFound", err)
		}
	})
}

func TestSelectField(t *testing.T) {
	const content = "pw: not-a-field\n" +
		"URL: https://example.com/login\n" +
		"Username:   bob  \n" +
		"empty:\n" +
		"no colon on this line\n" +
		"url: second-url-is-ignored\n" +
		"time: 12:30:45\n" +
		"Security Question: first pet\r\n"

	tests := []struct {
		field   string
		want    string
		wantErr bool
	}{
		{"username", "bob", false},
		{"USERNAME", "bob", false},
		{"URL", "https://example.com/login", false}, // the first match wins
		{"url", "https://example.com/login", false},
		{"empty", "", false},
		{"time", "12:30:45", false}, // only the first colon separates
		{"Security Question", "first pet", false},
		{"pw", "", true}, // the first line is the password, not a field
		{"missing", "", true},
		{"no colon on this line", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			ref, err := entry.Parse("p#" + tt.field)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ref.Select([]byte(content))
			if tt.wantErr {
				if !errors.Is(err, entry.ErrSelectorNotFound) {
					t.Fatalf("err = %v, want ErrSelectorNotFound", err)
				}
				return
			}
			if err != nil || string(got) != tt.want {
				t.Errorf("Select = %q, %v; want %q", got, err, tt.want)
			}
		})
	}

	t.Run("single line entry has no fields", func(t *testing.T) {
		ref, _ := entry.Parse("p#user")
		if _, err := ref.Select([]byte("user: x\n")); !errors.Is(err, entry.ErrSelectorNotFound) {
			t.Fatalf("err = %v, want ErrSelectorNotFound", err)
		}
	})

	t.Run("empty entry", func(t *testing.T) {
		ref, _ := entry.Parse("p#user")
		if _, err := ref.Select(nil); !errors.Is(err, entry.ErrSelectorNotFound) {
			t.Fatalf("err = %v, want ErrSelectorNotFound", err)
		}
	})
}
