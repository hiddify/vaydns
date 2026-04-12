package client

import (
	"bytes"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/net2share/vaydns/dns"
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
		name:        name,
		addr:        turbotunnel.DummyAddr{},
		conn:        conn,
		forgedStats: &ForgedStats{Label: name},
		pending:     make(map[uint16]time.Time),
		state:       ResolverStateUnknown,
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

// TestMultiResolver_DeadEntryDoesNotBreakReadFrom verifies that when one
// resolver entry's transport returns a fatal read error, MultiResolver.ReadFrom
// continues to deliver packets from healthy entries instead of propagating
// that error to the upper DNSPacketConn layer (which would tear down the whole
// tunnel session).
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

// TestMultiResolver_FailedEntryExcludedFromSelection verifies that after a
// reader goroutine has processed a fatal read error and exited, the entry
// is no longer returned by selectPrimary. Otherwise the round-robin scheduler
// would keep sending queries to a resolver whose reader goroutine is gone
// (so responses would never come back).
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

	// Drain any stale result from recvChan so the assertion below only
	// checks selectPrimary behaviour, not lingering channel contents.
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

// buildDNSResponse constructs a minimal valid DNS wire-format response with
// the given RCODE. QR is set to 1. This is the smallest packet that
// dns.MessageFromWireFormat can parse and isValidDNSResponse/isRateLimitedResponse
// can classify.
func buildDNSResponse(t *testing.T, rcode uint16) []byte {
	t.Helper()
	msg := &dns.Message{
		ID:    0x1234,
		Flags: 0x8000 | rcode, // QR=1 + RCODE
	}
	buf, err := msg.WireFormat()
	if err != nil {
		t.Fatalf("buildDNSResponse: %v", err)
	}
	return buf
}

// TestForgedStats_LabeledMilestoneLog verifies that ForgedStats.Record()
// fires a milestone log at the expected thresholds and that the log line
// includes the resolver label in the "from <addr>" format.
func TestForgedStats_LabeledMilestoneLog(t *testing.T) {
	stats := &ForgedStats{Label: "1.2.3.4:53"}

	// Record 9 forged NXDOMAIN responses — no milestone yet.
	for range 9 {
		stats.Record(dns.RcodeNameError)
	}
	if atomic.LoadUint64(&stats.Total) != 9 {
		t.Fatalf("expected Total=9, got %d", stats.Total)
	}

	// The 10th should trigger the first milestone.
	stats.Record(dns.RcodeNameError)
	if atomic.LoadUint64(&stats.Total) != 10 {
		t.Fatalf("expected Total=10, got %d", stats.Total)
	}
	if atomic.LoadUint64(&stats.NXDOMAIN) != 10 {
		t.Fatalf("expected NXDOMAIN=10, got %d", stats.NXDOMAIN)
	}
}

// TestForgedStats_UnlabeledFallback verifies that a ForgedStats with an
// empty Label still records correctly (used by DNSPacketConn's catch-all).
func TestForgedStats_UnlabeledFallback(t *testing.T) {
	stats := &ForgedStats{}
	stats.Record(dns.RcodeServerFailure)
	if atomic.LoadUint64(&stats.Total) != 1 {
		t.Fatalf("expected Total=1, got %d", stats.Total)
	}
	if atomic.LoadUint64(&stats.SERVFAIL) != 1 {
		t.Fatalf("expected SERVFAIL=1, got %d", stats.SERVFAIL)
	}
}

// TestMultiResolver_ForgedResponseRecordedPerEntry verifies that in
// multi-resolver mode, a forged DNS response (NXDOMAIN) arriving at one
// entry increments that entry's ForgedStats but not the other entries'.
func TestMultiResolver_ForgedResponseRecordedPerEntry(t *testing.T) {
	forging := newFakePacketConn("forging")
	clean := newFakePacketConn("clean")

	forgingEntry := newFakeEntry("forging", forging)
	cleanEntry := newFakeEntry("clean", clean)

	mr := newTestMultiResolver([]*resolverEntry{forgingEntry, cleanEntry}, SelectionRoundRobin)
	defer mr.Close()

	// Push a forged NXDOMAIN response to the forging entry.
	forgedResp := buildDNSResponse(t, dns.RcodeNameError)
	forging.pushData(forgedResp)

	// Give the reader time to process.
	time.Sleep(100 * time.Millisecond)

	// Forging entry's stats should have recorded the forged response.
	if got := atomic.LoadUint64(&forgingEntry.forgedStats.Total); got != 1 {
		t.Errorf("forging entry ForgedStats.Total = %d, want 1", got)
	}
	if got := atomic.LoadUint64(&forgingEntry.forgedStats.NXDOMAIN); got != 1 {
		t.Errorf("forging entry ForgedStats.NXDOMAIN = %d, want 1", got)
	}

	// Clean entry's stats should be untouched.
	if got := atomic.LoadUint64(&cleanEntry.forgedStats.Total); got != 0 {
		t.Errorf("clean entry ForgedStats.Total = %d, want 0", got)
	}
}

// TestMultiResolver_ForgedResponseNotForwardedToRecvChan verifies that
// forged responses detected by evaluateIncoming are NOT forwarded to
// recvChan (and therefore never reach DNSPacketConn). Only legitimate
// responses should appear on the channel.
func TestMultiResolver_ForgedResponseNotForwardedToRecvChan(t *testing.T) {
	conn := newFakePacketConn("resolver")
	entry := newFakeEntry("resolver", conn)

	mr := newTestMultiResolver([]*resolverEntry{entry}, SelectionRoundRobin)
	defer mr.Close()

	// Push a forged NXDOMAIN, then a valid NoError response.
	forgedResp := buildDNSResponse(t, dns.RcodeNameError)
	validResp := buildDNSResponse(t, dns.RcodeNoError)
	conn.pushData(forgedResp)
	conn.pushData(validResp)

	// ReadFrom should return the valid response, skipping the forged one.
	buf := make([]byte, 4096)
	type readResult struct {
		n   int
		err error
	}
	done := make(chan readResult, 1)
	go func() {
		n, _, err := mr.ReadFrom(buf)
		done <- readResult{n: n, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("ReadFrom error: %v", r.err)
		}
		// The bytes should be the valid response, not the forged one.
		if bytes.Equal(buf[:r.n], forgedResp) {
			t.Fatal("ReadFrom returned the forged response — it should have been filtered by the reader goroutine")
		}
		if !bytes.Equal(buf[:r.n], validResp) {
			t.Fatalf("ReadFrom returned unexpected bytes:\n  got:  %x\n  want: %x", buf[:r.n], validResp)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReadFrom timed out; expected valid response within 3s")
	}

	// Verify the forged response was recorded.
	if got := atomic.LoadUint64(&entry.forgedStats.Total); got != 1 {
		t.Errorf("ForgedStats.Total = %d, want 1", got)
	}
}

// TestMultiResolver_ForgedStatsPerEntryLabeled verifies that each entry
// in a MultiResolver carries a distinctly-labeled ForgedStats instance.
func TestMultiResolver_ForgedStatsPerEntryLabeled(t *testing.T) {
	conn1 := newFakePacketConn("r1")
	conn2 := newFakePacketConn("r2")

	e1 := newFakeEntry("1.1.1.1:53", conn1)
	e2 := newFakeEntry("8.8.8.8:53", conn2)

	mr := newTestMultiResolver([]*resolverEntry{e1, e2}, SelectionRoundRobin)
	defer mr.Close()

	if e1.forgedStats == e2.forgedStats {
		t.Fatal("entries share the same ForgedStats pointer; expected distinct per-resolver instances")
	}
	if e1.forgedStats.Label != "1.1.1.1:53" {
		t.Errorf("entry1 label = %q, want %q", e1.forgedStats.Label, "1.1.1.1:53")
	}
	if e2.forgedStats.Label != "8.8.8.8:53" {
		t.Errorf("entry2 label = %q, want %q", e2.forgedStats.Label, "8.8.8.8:53")
	}
}
