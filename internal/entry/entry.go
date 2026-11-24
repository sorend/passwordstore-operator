// Package entry parses and evaluates the references to password store entries that are used as
// values in the data of a PasswordStoreSecret.
//
// A reference is the path of an entry relative to the root of the store, without the .gpg suffix,
// optionally followed by a selector:
//
//	k8s/db/admin-user             the whole entry
//	k8s/db/admin-user#1           the first line, which pass treats as the password
//	k8s/db/admin-user#username    the value of the first "username: value" line after the first line
package entry

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// maxPathLength bounds the length of an entry path.
const maxPathLength = 1024

// Suffix is the extension of the files that pass writes encrypted entries to.
const Suffix = ".gpg"

var (
	// ErrInvalid means a reference is malformed.
	ErrInvalid = errors.New("invalid entry reference")
	// ErrSelectorNotFound means the entry has no line or field matching the selector.
	ErrSelectorNotFound = errors.New("selector matches nothing in the entry")
)

// SelectorKind says which part of an entry a Selector picks.
type SelectorKind int

const (
	// SelectAll picks the whole entry.
	SelectAll SelectorKind = iota
	// SelectLine picks a line by its number.
	SelectLine
	// SelectField picks the value of a "key: value" line by its key.
	SelectField
)

// Selector picks a part of a decrypted entry. The zero value picks the whole entry.
type Selector struct {
	Kind SelectorKind
	// Line is the 1-based number of the line for SelectLine.
	Line int
	// Field is the key for SelectField.
	Field string
}

// Ref refers to an entry of a password store and to a part of it.
type Ref struct {
	// Path is the path of the entry inside the store, using "/" as separator, without a
	// leading slash and without the .gpg suffix.
	Path     string
	Selector Selector
}

// Parse parses a reference, validating the path.
func Parse(value string) (Ref, error) {
	path, selector := splitSelector(value)

	path = strings.TrimLeft(path, "/")
	if err := validatePath(path); err != nil {
		return Ref{}, fmt.Errorf("%w %q: %w", ErrInvalid, value, err)
	}

	ref := Ref{Path: path}
	if selector != nil {
		sel, err := parseSelector(*selector)
		if err != nil {
			return Ref{}, fmt.Errorf("%w %q: %w", ErrInvalid, value, err)
		}
		ref.Selector = sel
	}
	return ref, nil
}

// splitSelector splits value at its last "#". A "#" that is followed by a "/" cannot start a
// selector, so it belongs to the path.
func splitSelector(value string) (path string, selector *string) {
	i := strings.LastIndex(value, "#")
	if i < 0 || strings.Contains(value[i+1:], "/") {
		return value, nil
	}
	sel := value[i+1:]
	return value[:i], &sel
}

func parseSelector(s string) (Selector, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Selector{}, errors.New("the selector after \"#\" is empty")
	}
	if isDigits(s) {
		line, err := strconv.Atoi(s)
		if err != nil || line < 1 {
			return Selector{}, fmt.Errorf("line number %q must be 1 or more", s)
		}
		return Selector{Kind: SelectLine, Line: line}, nil
	}
	if strings.ContainsAny(s, "\r\n\x00") {
		return Selector{}, errors.New("a field name cannot contain line breaks")
	}
	if strings.Contains(s, ":") {
		// The name of a field ends at the first colon of its line, so such a name could never be found.
		return Selector{}, errors.New("a field name cannot contain a colon")
	}
	return Selector{Kind: SelectField, Field: s}, nil
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func validatePath(path string) error {
	if path == "" {
		return errors.New("the path is empty")
	}
	if len(path) > maxPathLength {
		return fmt.Errorf("the path is longer than %d bytes", maxPathLength)
	}
	for _, c := range path {
		if c < 0x20 || c == 0x7f {
			return errors.New("the path contains a control character")
		}
		if c == '\\' {
			return errors.New("the path contains a backslash, use \"/\" as separator")
		}
	}
	for segment := range strings.SplitSeq(path, "/") {
		switch segment {
		case "":
			return errors.New("the path contains an empty segment, such as \"//\" or a trailing \"/\"")
		case ".", "..":
			return fmt.Errorf("the path contains %q, which is not allowed", segment)
		}
	}
	return nil
}

// Files returns the paths of the files in the store that can hold the entry, best match first.
// An entry is normally stored as <path>.gpg. A reference that already carries the .gpg suffix
// is accepted for convenience, as the name of the file.
func (r Ref) Files() []string {
	files := []string{r.Path + Suffix}
	if strings.HasSuffix(r.Path, Suffix) && len(r.Path) > len(Suffix) {
		files = append(files, r.Path)
	}
	return files
}

// String returns the reference in the form that Parse accepts.
func (r Ref) String() string {
	switch r.Selector.Kind {
	case SelectLine:
		return fmt.Sprintf("%s#%d", r.Path, r.Selector.Line)
	case SelectField:
		return r.Path + "#" + r.Selector.Field
	default:
		return r.Path
	}
}

// Select extracts the part of the decrypted entry that the reference selects.
//
// Without a selector the whole entry is returned. A trailing line break is removed if the entry
// is a single line, because passwords do not end in one while pass always writes one. Entries
// with more than one line, such as PEM files, are returned unchanged.
func (r Ref) Select(content []byte) ([]byte, error) {
	switch r.Selector.Kind {
	case SelectLine:
		lines := splitLines(string(content))
		if r.Selector.Line > len(lines) {
			return nil, fmt.Errorf("%w: entry has %d line(s), no line %d", ErrSelectorNotFound, len(lines), r.Selector.Line)
		}
		return []byte(lines[r.Selector.Line-1]), nil

	case SelectField:
		lines := splitLines(string(content))
		// The first line is the password, by convention of pass. It is not a field even if it
		// happens to contain a colon.
		for _, line := range lines[min(1, len(lines)):] {
			key, value, ok := strings.Cut(line, ":")
			if ok && strings.EqualFold(strings.TrimSpace(key), r.Selector.Field) {
				return []byte(strings.TrimSpace(value)), nil
			}
		}
		return nil, fmt.Errorf("%w: entry has no field %q", ErrSelectorNotFound, r.Selector.Field)

	default:
		return trimSingleLine(content), nil
	}
}

// splitLines splits text into lines without their terminators. A line break at the very end
// does not start another line.
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines
}

// trimSingleLine removes the line terminator at the end of content that consists of one line.
func trimSingleLine(content []byte) []byte {
	n := len(content)
	if n == 0 || content[n-1] != '\n' {
		return content
	}
	body := content[:n-1]
	if bytes.IndexByte(body, '\n') >= 0 {
		return content
	}
	return bytes.TrimSuffix(body, []byte("\r"))
}
