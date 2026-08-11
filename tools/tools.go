// Package tools implements the PAN-OS MCP tool handlers.
package tools

import (
	"log/slog"
	"sync"
	"time"

	"github.com/PaloAltoNetworks/pango"
)

// Deps carries the shared dependencies for all tool handlers.
type Deps struct {
	Client     *pango.Client
	Logger     *slog.Logger
	IsPanorama bool
	ReadOnly   bool
	JobWait    time.Duration

	// writeMu serializes every mutation: PAN-OS has one shared candidate
	// config per device, and interleaved read-modify-write cycles corrupt it.
	writeMu sync.Mutex
}

// LockWrites takes the mutation lock and returns the unlock function. Callers
// must capture the result and defer it:
//
//	unlock := d.LockWrites()
//	defer unlock()
//
// Do not write "defer d.LockWrites()": defer evaluates the call at function
// exit, so the body would run unlocked and the lock would then be taken and
// never released.
func (d *Deps) LockWrites() func() {
	d.writeMu.Lock()
	return d.writeMu.Unlock
}
