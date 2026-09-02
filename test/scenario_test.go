package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	anytls "github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type proxyDialer func(ctx context.Context, destination M.Socksaddr) (net.Conn, error)

func echoOnce(t *testing.T, dial proxyDialer, echo M.Socksaddr, payloadLen int, singleWrite bool) {
	t.Helper()
	conn, err := dial(context.Background(), echo)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
	payload := make([]byte, payloadLen)
	_, err = rand.Read(payload)
	require.NoError(t, err)
	received := make([]byte, payloadLen)
	var writeErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if singleWrite {
			_, writeErr = conn.Write(payload)
			return
		}
		for offset := 0; offset < payloadLen; {
			var written int
			written, writeErr = conn.Write(payload[offset:min(offset+32*1024, payloadLen)])
			if writeErr != nil {
				return
			}
			offset += written
		}
	}()
	_, err = io.ReadFull(conn, received)
	wg.Wait()
	require.NoError(t, writeErr, "write at length %d", payloadLen)
	require.NoError(t, err, "read at length %d", payloadLen)
	require.True(t, bytes.Equal(payload, received), "payload mismatch at length %d", payloadLen)
}

func echoScenario(t *testing.T, dial proxyDialer, echo M.Socksaddr) {
	t.Helper()
	for _, payloadLen := range []int{1, 1024, 65535, 65536, 100 * 1024, 2 * 1024 * 1024} {
		echoOnce(t, dial, echo, payloadLen, false)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			echoOnce(t, dial, echo, 256*1024, false)
		}()
	}
	wg.Wait()
}

func TestLoopback(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newService(t, nil, nil))
	client := newClient(t, server)
	echoScenario(t, client.DialContext, echo)
}

func TestLoopbackCustomPadding(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newService(t, customPaddingScheme, nil))
	client := newClient(t, server)
	echoScenario(t, client.DialContext, echo)
}

// A padding record larger than one frame has to be filled with several waste frames;
// a single truncated length field would desynchronise the peer's frame parser.
func TestLoopbackOversizedPaddingRecords(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newService(t, oversizedPaddingRecords, nil))
	client := newClient(t, server)
	echoScenario(t, client.DialContext, echo)
}

// A scheme whose text does not fit in a frame cannot be pushed to the client, which
// keeps its own scheme; the session has to survive that disagreement.
func TestLoopbackUnsendablePaddingScheme(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newService(t, unsendablePaddingScheme(), nil))
	client := newClient(t, server)
	echoScenario(t, client.DialContext, echo)
}

func TestLoopbackMultiUser(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newMultiService(t))
	client := newClient(t, server)
	echoScenario(t, client.DialContext, echo)
}

func TestClientAgainstUpstreamService(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newUpstreamService(t, nil))
	client := newClient(t, server)
	echoScenario(t, client.DialContext, echo)
}

func TestClientAgainstUpstreamServiceCustomPadding(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newUpstreamService(t, customPaddingScheme))
	client := newClient(t, server)
	echoScenario(t, client.DialContext, echo)
}

func TestUpstreamClientAgainstService(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newService(t, nil, nil))
	client := newUpstreamClient(t, server)
	echoScenario(t, client.CreateProxy, echo)
}

func TestUpstreamClientAgainstServiceCustomPadding(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newService(t, customPaddingScheme, nil))
	client := newUpstreamClient(t, server)
	echoScenario(t, client.CreateProxy, echo)
}

func TestSessionReuse(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newService(t, nil, nil))
	var dialed atomic.Int32
	client, err := anytls.NewClient(anytls.ClientOptions{
		Password: testPassword,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			dialed.Add(1)
			return net.Dial(N.NetworkTCP, server.String())
		},
		Logger: logger.NOP(),
	})
	require.NoError(t, err)
	defer client.Close()
	for range 16 {
		echoOnce(t, client.DialContext, echo, 4096, false)
	}
	require.Equal(t, int32(1), dialed.Load(), "expected a single reused session")
}

func TestFallback(t *testing.T) {
	t.Parallel()
	server := startService(t, newService(t, nil, echoHandler{}))
	conn, err := net.Dial(N.NetworkTCP, server.String())
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write(bytes.Repeat([]byte{0x11}, 64))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	received := make([]byte, 8)
	_, err = io.ReadFull(conn, received)
	require.NoError(t, err)
	require.Equal(t, "fallback", string(received))
}

func TestHandshakeFailure(t *testing.T) {
	t.Parallel()
	server := startService(t, newService(t, nil, nil))
	client := newClient(t, server)
	conn, err := client.DialContext(context.Background(), closedPort(t))
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = conn.Read(make([]byte, 1))
	require.Error(t, err)
	require.NotErrorIs(t, err, io.EOF)
}

func TestOversizedSingleWrite(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newService(t, nil, nil))
	client := newClient(t, server)
	for _, payloadLen := range []int{65536, 512 * 1024} {
		echoOnce(t, client.DialContext, echo, payloadLen, true)
	}
}

func TestOversizedSingleWriteAgainstUpstreamService(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newUpstreamService(t, nil))
	client := newClient(t, server)
	for _, payloadLen := range []int{65536, 512 * 1024} {
		echoOnce(t, client.DialContext, echo, payloadLen, true)
	}
}
