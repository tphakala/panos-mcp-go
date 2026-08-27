package tools

import (
	"testing"

	"github.com/PaloAltoNetworks/pango/device/profiles/email"
	"github.com/PaloAltoNetworks/pango/device/profiles/radius"
)

// TestRadiusProfileOverlayReplaceAndPreserve pins the update contract for the
// RADIUS family: an overlay providing nothing preserves the stored servers
// (and their secrets) and scalar fields; an overlay providing a servers list
// replaces the stored list, while merging existing servers by name so an omitted
// per-server secret is preserved.
func TestRadiusProfileOverlayReplaceAndPreserve(t *testing.T) {
	e := &radius.Entry{
		Name: "rad", Retries: new(int64(3)), Timeout: new(int64(5)),
		Server: []radius.Server{{Name: "s1", IpAddress: new("10.0.0.1"), Secret: new("stored")}},
	}
	if err := overlayRadiusProfile(e, RadiusProfileInput{Name: "rad"}); err != nil {
		t.Fatal(err)
	}
	mustInt64(t, e.Retries, 3, "retries preserved")
	mustInt64(t, e.Timeout, 5, "timeout preserved")
	if len(e.Server) != 1 {
		t.Fatalf("expected 1 server preserved, got %d", len(e.Server))
	}
	mustStrPtr(t, e.Server[0].Secret, "stored", "s1 secret preserved")

	// Provided servers list replaces the stored list: absent s1 is removed, s2 is added.
	if err := overlayRadiusProfile(e, RadiusProfileInput{Name: "rad", Servers: []RadiusServerInput{{Name: "s2", IpAddress: new("10.0.0.2"), Secret: new("fresh")}}}); err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 1 || e.Server[0].Name != "s2" {
		t.Fatalf("server list must replace with s2: %+v", e.Server)
	}
	mustStrPtr(t, e.Server[0].Secret, "fresh", "s2 fresh secret")

	// Merge-by-name on existing server preserves omitted secret.
	if err := overlayRadiusProfile(e, RadiusProfileInput{Name: "rad", Servers: []RadiusServerInput{{Name: "s2", IpAddress: new("10.0.0.3")}}}); err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 1 || e.Server[0].Name != "s2" {
		t.Fatalf("s2 must remain: %+v", e.Server)
	}
	mustStrPtr(t, e.Server[0].IpAddress, "10.0.0.3", "s2 updated address")
	mustStrPtr(t, e.Server[0].Secret, "fresh", "s2 preserved secret")
}

// TestEmailProfileOverlayReplaceAndPreserve pins the update contract for the
// email family: an overlay providing nothing preserves the stored servers
// (and their passwords); an overlay providing a servers list replaces the stored
// list, while merging existing servers by name so an omitted SMTP password is
// preserved.
func TestEmailProfileOverlayReplaceAndPreserve(t *testing.T) {
	e := &email.Entry{
		Name:   "em",
		Server: []email.Server{{Name: "s1", Gateway: new("smtp1.example.com"), Password: new("stored")}},
	}
	if err := overlayEmailProfile(e, EmailProfileInput{Name: "em"}); err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 1 {
		t.Fatalf("expected 1 server preserved, got %d", len(e.Server))
	}
	mustStrPtr(t, e.Server[0].Gateway, "smtp1.example.com", "s1 gateway preserved")
	mustStrPtr(t, e.Server[0].Password, "stored", "s1 password preserved")

	// Provided servers list replaces the stored list: absent s1 is removed, s2 is added.
	if err := overlayEmailProfile(e, EmailProfileInput{Name: "em", Servers: []EmailServerInput{{Name: "s2", Gateway: new("smtp2.example.com"), Password: new("fresh")}}}); err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 1 || e.Server[0].Name != "s2" {
		t.Fatalf("server list must replace with s2: %+v", e.Server)
	}
	mustStrPtr(t, e.Server[0].Password, "fresh", "s2 fresh password")

	// Merge-by-name on existing server preserves omitted password.
	if err := overlayEmailProfile(e, EmailProfileInput{Name: "em", Servers: []EmailServerInput{{Name: "s2", Gateway: new("smtp3.example.com")}}}); err != nil {
		t.Fatal(err)
	}
	if len(e.Server) != 1 || e.Server[0].Name != "s2" {
		t.Fatalf("s2 must remain: %+v", e.Server)
	}
	mustStrPtr(t, e.Server[0].Gateway, "smtp3.example.com", "s2 updated gateway")
	mustStrPtr(t, e.Server[0].Password, "fresh", "s2 preserved password")
}
