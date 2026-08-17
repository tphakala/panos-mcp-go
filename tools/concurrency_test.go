package tools

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// raceEntry is the entry type for the read-lock race test.
type raceEntry struct{ Name string }

// raceState stands in for the unsynchronized fields of a real *pango.Client: a
// reader reads n while a writer mutates it, and writing is true only while the
// writer holds the exclusive lock. The RWMutex in Deps is the ONLY thing
// ordering these accesses. Drop the read lock from a read handler and two things
// go wrong at once: -race reports the concurrent access to n, and a reader can
// observe writing == true (counted in violations), so the test fails even
// without the race detector.
type raceState struct {
	n          int
	writing    bool
	violations atomic.Int64
}

// raceService feeds the read (List/Read) path from raceState. Create, Update and
// Delete exist only to satisfy crudService; the writer goroutine mutates the
// state directly under LockWrites rather than through them.
type raceService struct{ st *raceState }

func (s raceService) observe() {
	if s.st.writing {
		s.st.violations.Add(1)
	}
}

func (s raceService) List(_ context.Context, _ struct{}, _, _, _ string) ([]*raceEntry, error) {
	s.observe()
	// Read n into the result so the compiler cannot elide the load the race
	// detector needs to see.
	return []*raceEntry{{Name: strconv.Itoa(s.st.n)}}, nil
}

func (s raceService) Read(_ context.Context, _ struct{}, _, _ string) (*raceEntry, error) {
	s.observe()
	return &raceEntry{Name: strconv.Itoa(s.st.n)}, nil
}

func (s raceService) Create(_ context.Context, _ struct{}, e *raceEntry) (*raceEntry, error) {
	return e, nil
}

func (s raceService) Update(_ context.Context, _ struct{}, e *raceEntry, _ string) (*raceEntry, error) {
	return e, nil
}

func (s raceService) Delete(_ context.Context, _ struct{}, _ ...string) error { return nil }

// TestReadHandlersHoldReadLock pins that listHandler and getHandler take the
// shared read lock, so they never run concurrently with a writer holding
// LockWrites. Run under `go test -race` (task go:test does). Deleting the
// `defer d.RLockReads()()` from listHandler makes the list path race with the
// writer; deleting it from getHandler does the same for the get path. The
// deterministic guard is the -race detector, which fires on the concurrent
// access to st.n/st.writing; st.violations is a strong statistical backstop for
// a run without -race (observed ~1000 per sabotage, though not a hard guarantee).
func TestReadHandlersHoldReadLock(t *testing.T) {
	st := &raceState{}
	d := &Deps{Logger: slog.New(slog.DiscardHandler)}
	svc := raceService{st: st}
	resolve := func(LocationInput) (struct{}, error) { return struct{}{}, nil }
	list := listHandler[struct{}, raceEntry](d, "race_list", svc, resolve,
		func(e *raceEntry) string { return e.Name },
		func(e *raceEntry) any { return e.Name })
	get := getHandler[struct{}, raceEntry](d, "race_get", svc, resolve)

	ctx := t.Context()

	// Writer runs until stopped, toggling writing around a mutation of n while
	// holding the exclusive lock.
	stop := make(chan struct{})
	var writerWG sync.WaitGroup
	writerWG.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			unlock := d.LockWrites()
			st.writing = true
			st.n++
			st.writing = false
			unlock()
		}
	})

	// Readers drive the real handler closures, half through list and half through
	// get, so both read-lock sites are exercised.
	const (
		readers = 8
		iters   = 500
	)
	var readersWG sync.WaitGroup
	for i := range readers {
		readersWG.Go(func() {
			for range iters {
				if i%2 == 0 {
					_, _, _ = list(ctx, nil, ListInput{})
				} else {
					_, _, _ = get(ctx, nil, NameInput{Name: "z"})
				}
			}
		})
	}

	readersWG.Wait()
	close(stop)
	writerWG.Wait()

	if v := st.violations.Load(); v != 0 {
		t.Fatalf("read handler observed a write in progress %d time(s): read lock does not exclude writers", v)
	}
}
