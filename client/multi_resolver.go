package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/turbotunnel"
	log "github.com/sirupsen/logrus"
)

// ResolverState is the current health state of one resolver.
type ResolverState string

const (
	ResolverStateUnknown     ResolverState = "unknown"
	ResolverStateHealthy     ResolverState = "healthy"
	ResolverStateRateLimited ResolverState = "rate_limited"
	ResolverStateDown        ResolverState = "down"
)

const (
	pendingResponseTimeout = 5 * time.Second
	healthTickInterval     = 1 * time.Second
	downTimeoutThreshold   = int64(8)
	rateLimitThreshold     = int64(5)
	probeInterval          = 1 * time.Second
)

// ResolverStat is a snapshot of one resolver's counters and health state.
type ResolverStat struct {
	Address      string
	State        ResolverState
	ValidCount   int64
	InvalidCount int64
	TimeoutCount int64
	LastWrite    time.Time
	LastValid    time.Time
}

type resolverEntry struct {
	name string
	addr net.Addr
	conn net.PacketConn

	// dead is set when the entry's transport has reported an unrecoverable
	// error and its reader goroutine has exited. A dead entry is permanently
	// excluded from selection and never transitions back — the only way to
	// recover is to rebuild the entire MultiResolver (which happens on a
	// full tunnel reconnect). Kept as an atomic.Bool so selection helpers
	// can read it without acquiring mu on the hot path.
	dead atomic.Bool

	// forgedStats tracks forged DNS response counters for this specific
	// resolver entry, with milestone logging attributed to its address.
	// In multi-resolver mode each entry owns its own labeled instance;
	// in single-resolver mode the Tunnel shares one instance with both
	// UDPPacketConn and DNSPacketConn.
	forgedStats *ForgedStats

	// mu protects every field below. Counters are deliberately not atomic:
	// the decay path in recomputeState would lose concurrent Adds if the
	// counters were atomic and decremented via Load→Store, and splitting
	// decay across a CAS loop is uglier than just holding mu for the
	// short window each counter update requires.
	mu           sync.Mutex
	validCount   int64
	invalidCount int64
	timeoutCount int64
	pending      map[uint16]time.Time
	lastWrite    time.Time
	lastValid    time.Time
	lastProbe    time.Time
	state        ResolverState
}

// markDead transitions the entry to a permanent Down state. It is idempotent
// and returns true only when this call was the one that transitioned the
// entry — callers rely on this to avoid double-counting the entry in
// MultiResolver.aliveCount when multiple goroutines detect the same transport
// failure concurrently.
//
// The dead flag and the state field are set together under mu so that
// recomputeState (also holding mu) cannot observe an inconsistent snapshot
// where dead is set but state has not yet been transitioned to Down.
func (e *resolverEntry) markDead() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dead.Load() {
		return false
	}
	e.dead.Store(true)
	e.state = ResolverStateDown
	return true
}

// isDead reports whether markDead has been called on this entry.
func (e *resolverEntry) isDead() bool {
	return e.dead.Load()
}

func (e *resolverEntry) writePacket(b []byte) (int, error) {
	now := time.Now()
	e.trackOutgoingID(b, now)
	n, err := e.conn.WriteTo(b, e.addr)
	e.mu.Lock()
	e.lastWrite = now
	if err != nil {
		e.invalidCount++
	}
	e.mu.Unlock()
	return n, err
}

func (e *resolverEntry) trackOutgoingID(b []byte, now time.Time) {
	msg, err := dns.MessageFromWireFormat(b)
	if err != nil {
		return
	}
	e.mu.Lock()
	e.pending[msg.ID] = now
	e.mu.Unlock()
}

func (e *resolverEntry) readPacket() (multiReadResult, bool) {
	var result multiReadResult
	result.entry = e
	result.n, result.addr, result.err = e.conn.ReadFrom(result.buf[:])
	var forged bool
	if result.err == nil {
		forged = e.evaluateIncoming(result.buf[:result.n])
	}
	return result, forged
}

// evaluateIncoming parses an incoming DNS response for health tracking and
// forged-response detection. Returns true when the response is forged
// (QR=1, RCODE != NoError) — the caller should not forward it upstream
// because evaluateIncoming already recorded it in the entry's ForgedStats.
func (e *resolverEntry) evaluateIncoming(packet []byte) bool {
	now := time.Now()
	resp, err := dns.MessageFromWireFormat(packet)
	if err != nil {
		e.mu.Lock()
		e.invalidCount++
		e.mu.Unlock()
		e.recomputeState(now)
		return false // parse error — not forged, let upper layer handle
	}

	if isValidDNSResponse(resp) {
		e.mu.Lock()
		delete(e.pending, resp.ID)
		e.validCount++
		e.timeoutCount = 0
		e.lastValid = now
		e.state = ResolverStateHealthy
		e.mu.Unlock()
		return false
	}

	// Non-valid DNS response. Track it for health purposes.
	rcode := resp.Flags & 0x000f
	isResponse := resp.Flags&0x8000 != 0

	e.mu.Lock()
	delete(e.pending, resp.ID)
	e.invalidCount++
	// Rate-limit classification is handled by the accumulation path in
	// recomputeState (invalidCount >= threshold && validCount == 0), not
	// by a direct state assignment here. recomputeState unconditionally
	// reassigns e.state, so any direct assignment would be immediately
	// overwritten.
	e.mu.Unlock()
	e.recomputeState(now)

	// Record in per-resolver forged stats and signal caller not to forward.
	// forgedStats is always non-nil in multi-resolver mode (set at entry
	// construction). The nil guard is defensive for any future caller that
	// constructs a resolverEntry without setting forgedStats.
	if isResponse && e.forgedStats != nil {
		e.forgedStats.Record(rcode)
		return true
	}
	return false
}

func (e *resolverEntry) expirePending(now time.Time) {
	e.mu.Lock()
	expired := int64(0)
	for id, t := range e.pending {
		if now.Sub(t) >= pendingResponseTimeout {
			delete(e.pending, id)
			expired++
		}
	}
	if expired > 0 {
		e.timeoutCount += expired
		e.invalidCount += expired
	} else {
		// Decay counters only when nothing accumulated this tick.
		// This ensures burst expirations (and response-driven
		// invalidCount growth between ticks) can outpace the decay
		// and eventually cross the detection thresholds. Decay runs
		// at most once per health-tick interval (~1s).
		if e.invalidCount > 0 {
			e.invalidCount--
		}
		if e.timeoutCount > 0 {
			e.timeoutCount--
		}
	}
	e.mu.Unlock()
	e.recomputeState(now)
}

func (e *resolverEntry) recomputeState(now time.Time) {
	// Dead is sticky — never recompute it back to any other state. We
	// re-check under the lock after acquiring it, in case markDead raced
	// in between the outer check and acquiring the lock.
	if e.isDead() {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dead.Load() {
		return
	}

	switch {
	case e.timeoutCount >= downTimeoutThreshold:
		e.state = ResolverStateDown
	case e.invalidCount >= rateLimitThreshold && e.validCount == 0:
		e.state = ResolverStateRateLimited
	case e.validCount > 0 && now.Sub(e.lastValid) <= 30*time.Second:
		e.state = ResolverStateHealthy
	case e.validCount == 0:
		e.state = ResolverStateUnknown
	default:
		e.state = ResolverStateUnknown
	}
}

func (e *resolverEntry) stateSnapshot() ResolverState {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}

func (e *resolverEntry) markProbe(now time.Time) {
	e.mu.Lock()
	e.lastProbe = now
	e.mu.Unlock()
}

func (e *resolverEntry) canProbe(now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return now.Sub(e.lastProbe) >= probeInterval
}

func (e *resolverEntry) snapshot() ResolverStat {
	e.mu.Lock()
	defer e.mu.Unlock()
	return ResolverStat{
		Address:      e.name,
		State:        e.state,
		ValidCount:   e.validCount,
		InvalidCount: e.invalidCount,
		TimeoutCount: e.timeoutCount,
		LastWrite:    e.lastWrite,
		LastValid:    e.lastValid,
	}
}

type multiReadResult struct {
	buf   [4096]byte
	n     int
	addr  net.Addr
	err   error
	entry *resolverEntry
}

// MultiResolver is a net.PacketConn that multiplexes across multiple DNS
// resolver transport connections. It tracks per-resolver health from valid and
// invalid responses, avoids down resolvers for primary traffic, and probes
// unhealthy resolvers by duplicating selected packets.
type MultiResolver struct {
	entries   []*resolverEntry
	mu        sync.Mutex
	rrIndex   int
	probeRR   int
	recvChan  chan multiReadResult
	closed    chan struct{}
	closeOnce sync.Once

	// aliveCount tracks how many entries still have a live reader
	// goroutine. When it reaches zero, allDead is closed, causing pending
	// ReadFrom/WriteTo calls to return an "all resolvers down" error,
	// which is the only condition that should propagate a transport
	// error to the upper tunnel session.
	aliveCount  atomic.Int32
	allDead     chan struct{}
	allDeadOnce sync.Once
}

// NewMultiResolver creates a MultiResolver from a slice of Resolver configs.
func NewMultiResolver(resolvers []Resolver, queueSize int, overflowMode turbotunnel.QueueOverflowMode) (*MultiResolver, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("at least one resolver is required")
	}

	entries := make([]*resolverEntry, 0, len(resolvers))
	for _, r := range resolvers {
		entryStats := &ForgedStats{Label: r.ResolverAddr}
		conn, addr, err := GetResolverConnection(r, queueSize, overflowMode, entryStats)
		if err != nil {
			for _, e := range entries {
				e.conn.Close()
			}
			return nil, fmt.Errorf("resolver %s %s: %w", r.ResolverType, r.ResolverAddr, err)
		}
		entries = append(entries, &resolverEntry{
			name:        r.ResolverAddr,
			addr:        addr,
			conn:        conn,
			forgedStats: entryStats,
			pending:     make(map[uint16]time.Time),
			state:       ResolverStateUnknown,
		})
	}

	log.Infof("multi-resolver: %d resolvers configured", len(entries))
	udpWorkerTotal := 0
	for i, r := range resolvers {
		log.Infof("  [%d] %s %s", i+1, r.ResolverType, r.ResolverAddr)
		if r.ResolverType == ResolverTypeUDP && !r.UDPSharedSocket {
			workers := r.UDPWorkers
			if workers <= 0 {
				workers = DefaultUDPWorkers
			}
			udpWorkerTotal += workers
		}
	}
	if udpWorkerTotal > 0 {
		log.Infof("multi-resolver: %d total UDP worker goroutines", udpWorkerTotal)
	}

	mr := &MultiResolver{
		entries:  entries,
		recvChan: make(chan multiReadResult, len(entries)*4),
		closed:   make(chan struct{}),
		allDead:  make(chan struct{}),
	}
	mr.aliveCount.Store(int32(len(entries)))
	mr.startReaders()
	go mr.healthWorker()
	return mr, nil
}

// entryDied is called whenever a transport error is observed for an entry,
// either from its reader goroutine or from a failed write. It marks the entry
// dead and, if this was the transition from alive to dead (as opposed to a
// second observer of the same failure), decrements aliveCount. When the last
// alive entry dies, allDead is closed so pending ReadFrom/WriteTo callers can
// unblock with a terminal error.
func (mr *MultiResolver) entryDied(entry *resolverEntry, err error) {
	if !entry.markDead() {
		return
	}
	log.Warnf("multi-resolver: entry %s transport error: %v; marking down", entry.name, err)
	if mr.aliveCount.Add(-1) == 0 {
		mr.allDeadOnce.Do(func() { close(mr.allDead) })
	}
}

// startReaders launches one reader goroutine per entry. Each goroutine reads
// packets from its entry's transport and pushes the result onto recvChan.
// Extracted so tests can construct MultiResolver with synthetic entries.
//
// On a transport error, the reader calls entryDied to mark the entry dead and
// signal allDead when the last entry dies. It never pushes error-bearing
// results onto recvChan: doing so would surface a single resolver's failure
// to DNSPacketConn.recvLoop, which would tear down the entire tunnel session
// and defeat the point of having multiple resolvers.
func (mr *MultiResolver) startReaders() {
	for _, e := range mr.entries {
		entry := e
		go func() {
			for {
				res, forged := entry.readPacket()
				if res.err != nil {
					mr.entryDied(entry, res.err)
					return
				}
				if forged {
					// evaluateIncoming already recorded this in the
					// entry's per-resolver ForgedStats. Don't forward
					// to DNSPacketConn — its safety-net filter would
					// double-count it.
					continue
				}
				select {
				case mr.recvChan <- res:
				case <-mr.closed:
					return
				}
			}
		}()
	}
}

func (mr *MultiResolver) healthWorker() {
	ticker := time.NewTicker(healthTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			stats := make([]ResolverStat, 0, len(mr.entries))
			for _, e := range mr.entries {
				e.expirePending(now)
				stats = append(stats, e.snapshot())
			}
			log.Debug("\n" + renderResolverStatsTable(stats, now))
		case <-mr.closed:
			return
		}
	}
}

func renderResolverStatsTable(stats []ResolverStat, now time.Time) string {
	var b strings.Builder
	b.WriteString("+-------------------------+--------------+--------+---------+---------+-------------+-------------+\n")
	b.WriteString("| resolver                | state        | valid  | invalid | timeout | last_write  | last_valid  |\n")
	b.WriteString("+-------------------------+--------------+--------+---------+---------+-------------+-------------+\n")
	for _, s := range stats {
		lastWriteAgo := "-"
		if !s.LastWrite.IsZero() {
			lastWriteAgo = now.Sub(s.LastWrite).Truncate(time.Second).String()
		}
		lastValidAgo := "-"
		if !s.LastValid.IsZero() {
			lastValidAgo = now.Sub(s.LastValid).Truncate(time.Second).String()
		}
		fmt.Fprintf(&b, "| %-23.23s | %-12s | %6d | %7d | %7d | %11s | %11s |\n",
			s.Address,
			s.State,
			s.ValidCount,
			s.InvalidCount,
			s.TimeoutCount,
			lastWriteAgo,
			lastValidAgo,
		)
	}
	b.WriteString("+-------------------------+--------------+--------+---------+---------+-------------+-------------+")
	return b.String()
}

func isValidDNSResponse(resp dns.Message) bool {
	if resp.Flags&0x8000 == 0 {
		return false
	}
	return (resp.Flags & 0x000f) == dns.RcodeNoError
}

// ReadFrom receives a packet from whichever resolver responds first.
// It only returns an error when the MultiResolver has been closed or every
// entry has died; a single resolver's transport error is isolated at the
// reader goroutine and does not propagate here.
func (mr *MultiResolver) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	select {
	case <-mr.closed:
		return 0, nil, net.ErrClosed
	case res := <-mr.recvChan:
		n = copy(b, res.buf[:res.n])
		return n, turbotunnel.DummyAddr{}, nil
	case <-mr.allDead:
		// Drain any packet that was buffered by a reader before it
		// died, so packets already delivered by the transport are not
		// discarded in favour of the terminal error. No more readers
		// are pushing (allDead is closed only after every reader has
		// exited), so a non-blocking read here races only with the
		// mr.closed case above, which is handled on the next call.
		select {
		case res := <-mr.recvChan:
			n = copy(b, res.buf[:res.n])
			return n, turbotunnel.DummyAddr{}, nil
		default:
			return 0, nil, fmt.Errorf("multi-resolver: all resolvers are down")
		}
	}
}

// WriteTo sends b to the selected primary resolver and may duplicate b to one
// unhealthy resolver as a probe to detect recovery. If the primary's write
// fails, the entry is marked dead and WriteTo retries with the next alive
// entry. An error is returned only when the MultiResolver is closed or every
// entry has been marked dead.
func (mr *MultiResolver) WriteTo(b []byte, _ net.Addr) (n int, err error) {
	select {
	case <-mr.closed:
		return 0, net.ErrClosed
	case <-mr.allDead:
		return 0, fmt.Errorf("multi-resolver: all resolvers are down")
	default:
	}

	// Try entries until one accepts the write or all alive entries have
	// been exhausted. Each write error marks the entry dead.
	var primary *resolverEntry
	for attempts := 0; attempts < len(mr.entries); attempts++ {
		primary = mr.selectPrimary()
		if primary == nil {
			break
		}
		n, err = primary.writePacket(b)
		if err == nil {
			break
		}
		mr.entryDied(primary, err)
	}
	switch {
	case err != nil:
		return 0, fmt.Errorf("multi-resolver: all write attempts failed: %w", err)
	case primary == nil:
		return 0, fmt.Errorf("multi-resolver: no alive resolver for write")
	}

	if probe := mr.selectProbeTarget(primary); probe != nil {
		probe.markProbe(time.Now())
		_, _ = probe.writePacket(b)
	}
	return n, nil
}

// selectPrimary returns the entry that should receive the next outgoing
// query, or nil if every entry has been marked dead. The caller must handle
// nil (e.g., return an "all resolvers down" error).
func (mr *MultiResolver) selectPrimary() *resolverEntry {
	return mr.selectRoundRobinHealthy()
}

func (mr *MultiResolver) selectRoundRobinHealthy() *resolverEntry {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	if len(mr.entries) == 0 {
		return nil
	}

	start := mr.rrIndex
	// First pass: prefer Healthy or Unknown, skipping dead entries.
	for i := 0; i < len(mr.entries); i++ {
		idx := (start + i) % len(mr.entries)
		if mr.entries[idx].isDead() {
			continue
		}
		state := mr.entries[idx].stateSnapshot()
		if state == ResolverStateHealthy || state == ResolverStateUnknown {
			mr.rrIndex = (idx + 1) % len(mr.entries)
			return mr.entries[idx]
		}
	}
	// Second pass: accept any non-dead entry even if RateLimited/Down.
	for i := 0; i < len(mr.entries); i++ {
		idx := (start + i) % len(mr.entries)
		if mr.entries[idx].isDead() {
			continue
		}
		mr.rrIndex = (idx + 1) % len(mr.entries)
		return mr.entries[idx]
	}
	// Every entry is dead.
	return nil
}

func (mr *MultiResolver) selectProbeTarget(primary *resolverEntry) *resolverEntry {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	now := time.Now()
	for i := 0; i < len(mr.entries); i++ {
		idx := (mr.probeRR + i) % len(mr.entries)
		e := mr.entries[idx]
		if e == primary {
			continue
		}
		if e.isDead() {
			continue
		}
		state := e.stateSnapshot()
		if state == ResolverStateHealthy {
			continue
		}
		if e.canProbe(now) {
			mr.probeRR = (idx + 1) % len(mr.entries)
			return e
		}
	}
	return nil
}

// Close closes all underlying connections and stops the reader goroutines.
func (mr *MultiResolver) Close() error {
	mr.closeOnce.Do(func() {
		close(mr.closed)
		for _, e := range mr.entries {
			e.conn.Close()
		}
	})
	return nil
}

// LocalAddr returns the local address of the first underlying connection.
// The value is arbitrary (there is no single meaningful local address for a
// multi-resolver), but the method must exist to satisfy net.PacketConn.
// No caller uses the returned address for routing or logic decisions.
func (mr *MultiResolver) LocalAddr() net.Addr {
	return mr.entries[0].conn.LocalAddr()
}

// SetDeadline sets a deadline on all underlying connections.
func (mr *MultiResolver) SetDeadline(t time.Time) error {
	var last error
	for _, e := range mr.entries {
		if err := e.conn.SetDeadline(t); err != nil {
			last = err
		}
	}
	return last
}

// SetReadDeadline sets a read deadline on all underlying connections.
func (mr *MultiResolver) SetReadDeadline(t time.Time) error {
	var last error
	for _, e := range mr.entries {
		if err := e.conn.SetReadDeadline(t); err != nil {
			last = err
		}
	}
	return last
}

// SetWriteDeadline sets a write deadline on all underlying connections.
func (mr *MultiResolver) SetWriteDeadline(t time.Time) error {
	var last error
	for _, e := range mr.entries {
		if err := e.conn.SetWriteDeadline(t); err != nil {
			last = err
		}
	}
	return last
}

// GetResolverConnection creates the underlying transport net.PacketConn for r.
// For UDP per-query mode, forgedStats is passed to NewUDPPacketConn so
// forged-response milestone logs are attributed to this resolver. Callers
// may pass nil to let each layer create its own counter.
func GetResolverConnection(r Resolver, queueSize int, overflowMode turbotunnel.QueueOverflowMode, forgedStats *ForgedStats) (net.PacketConn, net.Addr, error) {
	switch r.ResolverType {
	case ResolverTypeUDP:
		addr, err := net.ResolveUDPAddr("udp", r.ResolverAddr)
		if err != nil {
			return nil, nil, err
		}
		if r.UDPSharedSocket {
			lc := net.ListenConfig{Control: r.DialerControl}
			conn, err := lc.ListenPacket(context.Background(), "udp", ":0")
			if err != nil {
				return nil, nil, err
			}
			return conn, addr, nil
		}
		workers := r.UDPWorkers
		if workers <= 0 {
			workers = DefaultUDPWorkers
		}
		timeout := r.UDPTimeout
		if timeout <= 0 {
			timeout = DefaultUDPResponseTimeout
		}
		conn, err := NewUDPPacketConn(addr, r.DialerControl, workers, timeout, !r.UDPAcceptErrors, queueSize, overflowMode, forgedStats)
		if err != nil {
			return nil, nil, err
		}
		return conn, addr, nil

	case ResolverTypeDOH:
		var rt http.RoundTripper
		if r.RoundTripper != nil {
			rt = r.RoundTripper
		} else if r.UTLSClientHelloID != nil {
			rt = NewUTLSRoundTripper(nil, r.UTLSClientHelloID)
		} else {
			rt = http.DefaultTransport
		}
		conn, err := NewHTTPPacketConn(rt, r.ResolverAddr, 8, queueSize, overflowMode)
		if err != nil {
			return nil, nil, err
		}
		return conn, turbotunnel.DummyAddr{}, nil

	case ResolverTypeDOT:
		var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
		if r.UTLSClientHelloID != nil {
			id := r.UTLSClientHelloID
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return UTLSDialContext(ctx, network, addr, nil, id)
			}
		} else {
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.DialWithDialer(&net.Dialer{}, network, addr, nil)
			}
		}
		conn, err := NewTLSPacketConn(r.ResolverAddr, dialTLSContext, queueSize, overflowMode)
		if err != nil {
			return nil, nil, err
		}
		return conn, turbotunnel.DummyAddr{}, nil

	default:
		return nil, nil, fmt.Errorf("unsupported resolver type: %s", r.ResolverType)
	}
}
