package test

import (
	"context"
	"crypto/rand"
	"io"
	mathrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStress(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newService(t, nil, nil))
	client := newClient(t, server)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 16 {
				echoOnce(t, client.DialContext, echo, 1+mathrand.IntN(96*1024), false)
			}
		}()
	}
	wg.Wait()
}

func TestAbortedStreams(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newService(t, nil, nil))
	client := newClient(t, server)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 16 {
				conn, err := client.DialContext(context.Background(), echo)
				require.NoError(t, err)
				payload := make([]byte, 1+mathrand.IntN(4096))
				_, err = rand.Read(payload)
				require.NoError(t, err)
				conn.Write(payload)
				if mathrand.IntN(2) == 0 {
					io.ReadFull(conn, make([]byte, len(payload)))
				}
				conn.Close()
			}
		}()
	}
	wg.Wait()
}

func TestDialAfterClose(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newService(t, nil, nil))
	client := newClient(t, server)
	echoOnce(t, client.DialContext, echo, 1024, false)
	require.NoError(t, client.Close())
	_, err := client.DialContext(context.Background(), echo)
	require.ErrorIs(t, err, net.ErrClosed)
}

// Two readers sharing one stream must not lose bytes: a partially consumed frame is
// cached on the stream, so an unsynchronised second reader would overwrite it.
func TestConcurrentReaders(t *testing.T) {
	t.Parallel()
	echo := startTCPEcho(t)
	server := startService(t, newService(t, nil, nil))
	client := newClient(t, server)
	conn, err := client.DialContext(context.Background(), echo)
	require.NoError(t, err)
	defer conn.Close()

	const total = 256 * 1024
	payload := make([]byte, total)
	_, err = rand.Read(payload)
	require.NoError(t, err)
	go func() {
		for offset := 0; offset < total; {
			written, writeErr := conn.Write(payload[offset:min(offset+4096, total)])
			if writeErr != nil {
				return
			}
			offset += written
		}
	}()

	var received atomic.Int64
	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buffer := make([]byte, 64)
			for {
				n, readErr := conn.Read(buffer)
				if n > 0 && received.Add(int64(n)) >= total {
					close(done)
					return
				}
				if readErr != nil {
					return
				}
			}
		}()
	}
	var stalled bool
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		stalled = true
	}
	conn.Close()
	wg.Wait()
	require.False(t, stalled, "lost %d of %d echoed bytes", total-received.Load(), total)
}
