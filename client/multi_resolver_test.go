package client

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/net2share/vaydns/turbotunnel"
)

// fakePacketConn is a controllable net.PacketConn for MultiResolver tests.
// Pushed responses are consumed in order by successive ReadFrom calls; each
// response can be either data bytes or an error.
type fakePacketConn struct {
	name   string
	readCh chan fakeReadResp
	closed chan struct{}
	once   sync.Once
}

type fakeReadResp struct {
	data []byte
	err  error
}

func newFakePacketConn(name string) *fakePacketConn {
	return &fakePacketConn{
		name:   name,
		readCh: make(chan fakeReadResp, 16),
		closed: make(chan struct{}),
	}
}

func (f *fakePacketConn) pushData(data []byte) {
	cp := make([]byte, len(data))
	copy(cp, data)
	f.readCh <- fakeReadResp{data: cp}
}

func (f *fakePacketConn) pushError(err error) {
	f.readCh <- fakeReadResp{err: err}
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case r, ok := <-f.readCh:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		if r.err != nil {
			return 0, nil, r.err
		}
		return copy(p, r.data), turbotunnel.DummyAddr{}, nil
	case <-f.closed:
		return 0, nil, net.ErrClosed
	}
}

func (f *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}

func (f *fakePacketConn) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakePacketConn) LocalAddr() net.Addr              { return turbotunnel.DummyAddr{} }
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

// newFakeEntry builds a resolverEntry around a fakePacketConn, suitable for
// injection into a hand-constructed MultiResolver in tests.
func newFakeEntry(name string, conn *fakePacketConn) *resolverEntry {
	return &resolverEntry{
		name:    name,
		addr:    turbotunnel.DummyAddr{},
		conn:    conn,
		pending: make(map[uint16]time.Time),
		state:   ResolverStateUnknown,
	}
}

// newTestMultiResolver mirrors what NewMultiResolver does after
// GetResolverConnection returns, but with pre-built synthetic entries. It does
// not spawn the healthWorker — tests don't need it, and omitting it keeps them
// hermetic with respect to timing.
func newTestMultiResolver(entries []*resolverEntry, mode SelectionMode) *MultiResolver {
	mr := &MultiResolver{
		entries:  entries,
		mode:     mode,
		recvChan: make(chan multiReadResult, len(entries)*4),
		closed:   make(chan struct{}),
		allDead:  make(chan struct{}),
	}
	mr.aliveCount.Store(int32(len(entries)))
	mr.startReaders()
	return mr
}

// TestMultiResolver_DeadEntryDoesNotBreakReadFrom exercises C1: when one
// resolver entry's transport returns a fatal read error, MultiResolver.ReadFrom
// must continue to deliver packets from healthy entries instead of propagating
// that error to the upper DNSPacketConn layer (which would tear down the whole
// tunnel session).
//
// Pre-fix expectation: this test FAILS — the reader goroutine pushes the error
// onto recvChan, ReadFrom returns it, and the test sees net.ErrClosed instead
// of the bytes from the working entry.
//
// Post-fix expectation: this test PASSES — the reader goroutine handles the
// error internally (e.g. marks the entry Down and exits), leaving recvChan to
// deliver only real response bytes from the surviving entries.
func TestMultiResolver_DeadEntryDoesNotBreakReadFrom(t *testing.T) {
	failing := newFakePacketConn("failing")
	working := newFakePacketConn("working")

	entries := []*resolverEntry{
		newFakeEntry("failing", failing),
		newFakeEntry("working", working),
	}
	mr := newTestMultiResolver(entries, SelectionRoundRobin)
	defer mr.Close()

	// Step 1: make the failing entry's ReadFrom return a fatal error.
	// The reader goroutine will pick this up immediately.
	failing.pushError(net.ErrClosed)

	// Give the reader goroutine time to handle the error. Under the buggy
	// implementation it pushes an error-bearing multiReadResult onto
	// recvChan and exits; under a correct implementation it would quietly
	// mark the entry down and exit without poisoning recvChan.
	time.Sleep(100 * time.Millisecond)

	// Step 2: push a valid response to the working entry. This lands on
	// recvChan strictly AFTER any push from the failing entry, so the
	// ordering is deterministic.
	wantResponse := []byte("valid-response-bytes-from-working-resolver")
	working.pushData(wantResponse)

	// Step 3: ReadFrom must return the bytes from the working entry, not
	// the error from the failing one.
	type readResult struct {
		n   int
		err error
		buf []byte
	}
	done := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _, err := mr.ReadFrom(buf)
		done <- readResult{n: n, err: err, buf: buf}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("MultiResolver.ReadFrom returned error %v; expected it to ignore the failed entry and return the bytes from the working entry. This is the C1 bug: a single resolver's read error tears down the tunnel.", r.err)
		}
		if !bytes.Equal(r.buf[:r.n], wantResponse) {
			t.Fatalf("MultiResolver.ReadFrom returned wrong bytes.\n  got:  %x\n  want: %x", r.buf[:r.n], wantResponse)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("MultiResolver.ReadFrom timed out; expected it to return bytes from the working entry within 3s")
	}
}

// TestMultiResolver_FailedEntryExcludedFromSelection exercises the selection
// side of C1: after a reader goroutine has processed a fatal read error and
// exited, the entry must no longer be returned by selectPrimary. Otherwise
// the round-robin scheduler will keep sending queries to a resolver whose
// reader goroutine is gone (so responses will never come back), defeating the
// health state machine.
//
// Pre-fix expectation: this test FAILS — the reader goroutine exits without
// updating the entry's state, so it remains ResolverStateUnknown, which
// selectRoundRobinHealthy treats as an acceptable target. The "failing" entry
// is returned roughly half the time.
//
// Post-fix expectation: this test PASSES — the reader goroutine transitions
// the entry to ResolverStateDown before exiting, and selectPrimary skips it.
func TestMultiResolver_FailedEntryExcludedFromSelection(t *testing.T) {
	failing := newFakePacketConn("failing")
	working := newFakePacketConn("working")

	entries := []*resolverEntry{
		newFakeEntry("failing", failing),
		newFakeEntry("working", working),
	}
	mr := newTestMultiResolver(entries, SelectionRoundRobin)
	defer mr.Close()

	// Kill the failing entry's reader; leave working blocked in ReadFrom.
	failing.pushError(net.ErrClosed)

	// Let the reader goroutine process the error and (ideally) mark the
	// entry down before it exits.
	time.Sleep(100 * time.Millisecond)

	// Drain any error result that the buggy reader may have pushed onto
	// recvChan. A correct reader wouldn't push anything here, so this
	// drain is a no-op post-fix. Without it, the buggy pre-fix state
	// machine would leave an error lingering, which isn't what this
	// specific assertion is about.
drain:
	for {
		select {
		case <-mr.recvChan:
		default:
			break drain
		}
	}

	// Call selectPrimary repeatedly. It must never return the failing
	// entry — otherwise real queries will be sent to a resolver whose
	// reader is gone, so responses will never come back.
	for i := range 10 {
		selected := mr.selectPrimary()
		if selected == nil {
			t.Fatalf("iter %d: selectPrimary returned nil", i)
		}
		if selected.name == "failing" {
			t.Fatalf("iter %d: selectPrimary returned the failed entry %q; expected it to be excluded after its reader exited on error. State is %s.", i, selected.name, selected.stateSnapshot())
		}
	}
}
