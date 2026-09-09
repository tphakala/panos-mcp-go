package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestHandleVersion pins the --version short-circuit: the recognized spellings
// print the build-stamped version and report handled (so runMain returns before
// LoadConfig), and anything else prints nothing and reports not handled so the
// normal startup path runs (issue #82). version is a package var; restore it.
func TestHandleVersion(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })
	version = "9.9.9-test"

	t.Run("recognized spellings print version and report handled", func(t *testing.T) {
		for _, arg := range []string{"-version", "--version"} {
			var buf bytes.Buffer
			if !handleVersion([]string{arg}, &buf) {
				t.Errorf("handleVersion([%q]) = false, want true", arg)
			}
			if got := strings.TrimSpace(buf.String()); got != version {
				t.Errorf("handleVersion([%q]) wrote %q, want %q", arg, got, version)
			}
		}
	})

	// A non-matching leading argument must not stop the scan; this pins that the
	// loop inspects every argument, not just the first.
	t.Run("version after another argument is still handled", func(t *testing.T) {
		var buf bytes.Buffer
		if !handleVersion([]string{"--unrelated", "--version"}, &buf) {
			t.Error("handleVersion with a later --version = false, want true")
		}
		if got := strings.TrimSpace(buf.String()); got != version {
			t.Errorf("wrote %q, want %q", got, version)
		}
	})

	t.Run("no version flag prints nothing and reports not handled", func(t *testing.T) {
		var buf bytes.Buffer
		if handleVersion([]string{"--other", "arg"}, &buf) {
			t.Error("handleVersion(non-version args) = true, want false")
		}
		if buf.Len() != 0 {
			t.Errorf("handleVersion(non-version args) wrote %q, want empty", buf.String())
		}
	})

	t.Run("empty args report not handled", func(t *testing.T) {
		var buf bytes.Buffer
		if handleVersion(nil, &buf) {
			t.Error("handleVersion(nil) = true, want false")
		}
	})
}
