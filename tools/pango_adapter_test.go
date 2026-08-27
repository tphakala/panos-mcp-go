package tools

import "testing"

// TestCheckNoRename pins the shared rename guard both CRUD adapters call. The
// guard is the only thing standing between a direct-caller name mismatch and
// pango's rename path, and its message is asserted verbatim elsewhere
// (vpn_write_test.go), so the empty-name pass-through and the mismatch
// rejection are both pinned here rather than only through a handler.
func TestCheckNoRename(t *testing.T) {
	tests := []struct {
		name      string
		update    string
		entry     string
		wantError bool
	}{
		{name: "blank update name means the entry's own name", update: "", entry: "prof-a"},
		{name: "matching names pass", update: "prof-a", entry: "prof-a"},
		{name: "mismatch is rejected", update: "prof-b", entry: "prof-a", wantError: true},
		{name: "blank entry name with a set update name is a mismatch", update: "prof-b", entry: "", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkNoRename(tt.update, tt.entry)
			if tt.wantError {
				if err == nil {
					t.Fatalf("checkNoRename(%q, %q) = nil, want an error", tt.update, tt.entry)
				}
				const want = "renaming is not supported: the update name \"prof-b\" must match the entry name "
				if got := err.Error(); len(got) < len(want) || got[:len(want)] != want {
					t.Errorf("checkNoRename(%q, %q) error = %q, want it to start with %q", tt.update, tt.entry, got, want)
				}
				return
			}
			if err != nil {
				t.Errorf("checkNoRename(%q, %q) = %v, want nil", tt.update, tt.entry, err)
			}
		})
	}
}
