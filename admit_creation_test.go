package anytls

// What a caller's creation admission may and may not see.
//
// The client has two paths with different costs. Reusing an idle session opens one stream; creating
// a session pays a TCP connect, a TLS handshake and the first write. A caller that bounds the
// expensive path must be consulted at the creation seam only, or a healthy reuse waits behind
// creations of other flows - the defect this option exists to remove.
//
// These tests pin the three properties the seam must have:
//  1. a new session asks for admission exactly once, and a reused session does not ask at all;
//  2. the hook owns the call, so a refusal means no dial happens;
//  3. the hook sees the creation's real error, which is what the caller's fast-fail policy and
//     permit release are computed from.

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// pipeDialer is a DialOut that never leaves the process. The peer drains everything so the client's
// settings write never blocks; the client's read loop then waits for frames that never arrive, which
// is exactly the idle state a reuse must be able to serve.
type pipeDialer struct {
	access sync.Mutex
	calls  int
	conns  []net.Conn
	err    error
}

func (d *pipeDialer) dial(context.Context) (net.Conn, error) {
	d.access.Lock()
	defer d.access.Unlock()
	d.calls++
	if d.err != nil {
		return nil, d.err
	}
	client, peer := net.Pipe()
	d.conns = append(d.conns, client, peer)
	go func() {
		_, _ = io.Copy(io.Discard, peer)
	}()
	return client, nil
}

func (d *pipeDialer) callCount() int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.calls
}

func (d *pipeDialer) close() {
	d.access.Lock()
	conns := d.conns
	d.conns = nil
	d.access.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func idleSessionCount(client *Client) int {
	client.access.Lock()
	defer client.access.Unlock()
	return client.idleSessions.Len()
}

func testDestination() M.Socksaddr {
	return M.Socksaddr{Fqdn: "example.com", Port: 443}
}

func newAdmittedClient(t *testing.T, dialer *pipeDialer, admitted *atomic.Int32) *Client {
	t.Helper()
	client, err := NewClient(ClientOptions{
		Password: "test-password",
		DialOut:  dialer.dial,
		AdmitCreation: func(ctx context.Context, create func(context.Context) error) error {
			admitted.Add(1)
			return create(ctx)
		},
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		dialer.close()
	})
	return client
}

// TestAdmitCreationIsAskedOnlyForANewSession is the Q10 contract: a pure reuse does not ask for a
// creation permit, so it cannot wait behind creations it is not part of.
func TestAdmitCreationIsAskedOnlyForANewSession(t *testing.T) {
	dialer := new(pipeDialer)
	admitted := new(atomic.Int32)
	client := newAdmittedClient(t, dialer, admitted)

	first, err := client.DialContext(context.Background(), testDestination())
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	if got := admitted.Load(); got != 1 {
		t.Fatalf("a new session asked for admission %d times, want 1", got)
	}
	if got := dialer.callCount(); got != 1 {
		t.Fatalf("a new session dialled %d times, want 1", got)
	}

	// Closing the only stream returns the session to the idle list, which is the state every later
	// demand is supposed to reuse.
	if err := first.Close(); err != nil {
		t.Fatalf("close first stream: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for idleSessionCount(client) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the session did not become idle after its last stream closed")
		}
		time.Sleep(time.Millisecond)
	}

	second, err := client.DialContext(context.Background(), testDestination())
	if err != nil {
		t.Fatalf("reuse dial: %v", err)
	}
	if got := admitted.Load(); got != 1 {
		t.Fatalf("a reused session asked for creation admission %d times, want 1", got)
	}
	if got := dialer.callCount(); got != 1 {
		t.Fatalf("a reused session dialled %d times, want 1", got)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close reused stream: %v", err)
	}
}

// TestAdmitCreationCanRefuseWithoutDialing pins that the hook owns the call: a refusal is not
// converted into a creation that happens anyway.
func TestAdmitCreationCanRefuseWithoutDialing(t *testing.T) {
	dialer := new(pipeDialer)
	refusal := errors.New("admission refused")
	client, err := NewClient(ClientOptions{
		Password: "test-password",
		DialOut:  dialer.dial,
		AdmitCreation: func(context.Context, func(context.Context) error) error {
			return refusal
		},
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		dialer.close()
	})

	if _, err = client.DialContext(context.Background(), testDestination()); !errors.Is(err, refusal) {
		t.Fatalf("dial returned %v, want the admission refusal", err)
	}
	if got := dialer.callCount(); got != 0 {
		t.Fatalf("a refused creation dialled %d times, want 0", got)
	}
}

// TestAdmitCreationSeesTheCreationError pins the input of the caller's outcome accounting: the hook
// must receive the error the creation actually produced, not a success.
func TestAdmitCreationSeesTheCreationError(t *testing.T) {
	dialer := &pipeDialer{err: net.ErrClosed}
	var observed error
	client, err := NewClient(ClientOptions{
		Password: "test-password",
		DialOut:  dialer.dial,
		AdmitCreation: func(ctx context.Context, create func(context.Context) error) error {
			observed = create(ctx)
			return observed
		},
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		dialer.close()
	})

	if _, err = client.DialContext(context.Background(), testDestination()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial returned %v, want the dial error", err)
	}
	if !errors.Is(observed, net.ErrClosed) {
		t.Fatalf("the admission hook observed %v, want the dial error", observed)
	}
}

// TestNoHookKeepsThePreviousBehaviour is the embedder contract: without AdmitCreation the client is
// exactly the previous one.
func TestNoHookKeepsThePreviousBehaviour(t *testing.T) {
	dialer := new(pipeDialer)
	client, err := NewClient(ClientOptions{Password: "test-password", DialOut: dialer.dial})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		dialer.close()
	})
	conn, err := client.DialContext(context.Background(), testDestination())
	if err != nil {
		t.Fatalf("dial without a hook: %v", err)
	}
	_ = conn.Close()
	if got := dialer.callCount(); got != 1 {
		t.Fatalf("dialled %d times, want 1", got)
	}
}
