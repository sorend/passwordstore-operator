package main

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseSize(t *testing.T) {
	tests := map[string]struct {
		in      string
		want    int64
		wantErr string
	}{
		"mebibytes":           {in: "64Mi", want: 64 << 20},
		"gibibytes":           {in: "1Gi", want: 1 << 30},
		"a plain number":      {in: "1048576", want: 1 << 20},
		"decimal megabytes":   {in: "10M", want: 10_000_000},
		"surrounding spaces":  {in: " 128Mi ", want: 128 << 20},
		"empty":               {in: "", wantErr: "not a size"},
		"words":               {in: "big", wantErr: "not a size"},
		"a unit that is none": {in: "64MB", wantErr: "not a size"},
		"zero":                {in: "0", wantErr: "more than zero"},
		"negative":            {in: "-1Mi", wantErr: "more than zero"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseSize("git-cache-size", tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || !strings.Contains(err.Error(), "--git-cache-size") {
					t.Fatalf("err = %v, want one with %q that names the flag", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("parseSize(%q) = %d, %v; want %d", tt.in, got, err, tt.want)
			}
		})
	}
}

func TestSplitHosts(t *testing.T) {
	tests := map[string]struct {
		in      string
		want    []string
		wantErr bool
	}{
		"nothing":         {in: "", want: nil},
		"only separators": {in: " , ,, ", want: nil},
		"one":             {in: "github.com", want: []string{"github.com"}},
		"several with spaces": {
			in: "github.com, gitlab.com ,git.example.org", want: []string{"github.com", "gitlab.com", "git.example.org"},
		},
		"a wildcard":               {in: "*.example.com", want: []string{"*.example.com"}},
		"an address":               {in: "10.0.0.5", want: []string{"10.0.0.5"}},
		"a scheme":                 {in: "https://github.com", wantErr: true},
		"a path":                   {in: "github.com/org", wantErr: true},
		"a port":                   {in: "github.com:22", wantErr: true},
		"a user":                   {in: "git@github.com", wantErr: true},
		"a wildcard in the middle": {in: "git.*.com", wantErr: true},
		"only a wildcard":          {in: "*", wantErr: true},
		"two wildcards":            {in: "*.*.com", wantErr: true},
		"a space inside":           {in: "git hub.com", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := splitHosts(tt.in)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "--allowed-git-hosts") {
					t.Fatalf("err = %v, want an error that names the flag", err)
				}
				return
			}
			if err != nil || !slices.Equal(got, tt.want) {
				t.Fatalf("splitHosts(%q) = %v, %v; want %v", tt.in, got, err, tt.want)
			}
		})
	}
}

func TestCheckDurations(t *testing.T) {
	if err := checkDurations(30*time.Second, 3*time.Minute); err != nil {
		t.Errorf("the defaults are fine: %v", err)
	}
	for name, args := range map[string][2]time.Duration{
		"no git timeout":                {0, 3 * time.Minute},
		"a negative git timeout":        {-time.Second, 3 * time.Minute},
		"a reconcile that is too short": {30 * time.Second, 30 * time.Second},
		"a reconcile that is shorter":   {30 * time.Second, 10 * time.Second},
	} {
		if err := checkDurations(args[0], args[1]); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
