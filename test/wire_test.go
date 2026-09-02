package test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	anytls "github.com/sagernet/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type recordedFrame struct {
	command  byte
	streamID uint32
}

type frameRecorder struct {
	access   sync.Mutex
	served   sync.WaitGroup
	listener net.Listener
	streams  [][]recordedFrame
}

func (r *frameRecorder) stop() {
	r.listener.Close()
	r.served.Wait()
}

func (r *frameRecorder) serve(conn net.Conn) {
	defer r.served.Done()
	defer conn.Close()
	r.access.Lock()
	index := len(r.streams)
	r.streams = append(r.streams, nil)
	r.access.Unlock()
	handshake := make([]byte, 34)
	_, err := io.ReadFull(conn, handshake)
	if err != nil {
		return
	}
	paddingLen := int(binary.BigEndian.Uint16(handshake[32:34]))
	if paddingLen > 0 {
		_, err = io.ReadFull(conn, make([]byte, paddingLen))
		if err != nil {
			return
		}
	}
	header := make([]byte, 7)
	for {
		_, err = io.ReadFull(conn, header)
		if err != nil {
			return
		}
		r.access.Lock()
		r.streams[index] = append(r.streams[index], recordedFrame{command: header[0], streamID: binary.BigEndian.Uint32(header[1:5])})
		r.access.Unlock()
		length := int(binary.BigEndian.Uint16(header[5:7]))
		if length > 0 {
			_, err = io.ReadFull(conn, make([]byte, length))
			if err != nil {
				return
			}
		}
	}
}

func startFrameRecorder(t *testing.T) (M.Socksaddr, *frameRecorder) {
	listener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		listener.Close()
	})
	recorder := &frameRecorder{listener: listener}
	recorder.served.Add(1)
	go func() {
		defer recorder.served.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			recorder.served.Add(1)
			go recorder.serve(conn)
		}
	}()
	return M.SocksaddrFromNet(listener.Addr()), recorder
}

// The reference server drops frames that name a stream it has not seen a SYN for,
// so nothing may reach the wire for a stream before its SYN.
func TestNoFrameBeforeSYN(t *testing.T) {
	t.Parallel()
	server, recorder := startFrameRecorder(t)
	client := newClient(t, server)
	destination := M.ParseSocksaddr("example.com:443")
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 16 {
				conn, err := client.DialContext(context.Background(), destination)
				require.NoError(t, err)
				start := make(chan struct{})
				var inner sync.WaitGroup
				inner.Add(2)
				go func() {
					defer inner.Done()
					<-start
					conn.Write([]byte("hello"))
				}()
				go func() {
					defer inner.Done()
					<-start
					conn.Close()
				}()
				close(start)
				inner.Wait()
			}
		}()
	}
	wg.Wait()
	require.NoError(t, client.Close())
	recorder.stop()

	recorder.access.Lock()
	defer recorder.access.Unlock()
	require.NotEmpty(t, recorder.streams, "no session recorded")
	var synCount int
	for _, frames := range recorder.streams {
		opened := make(map[uint32]bool)
		for _, frame := range frames {
			if frame.streamID == 0 {
				continue
			}
			if frame.command == 1 {
				opened[frame.streamID] = true
				synCount++
				continue
			}
			require.True(t, opened[frame.streamID], "command %d reached the wire before SYN for stream %d", frame.command, frame.streamID)
		}
	}
	require.NotZero(t, synCount, "no stream was opened")
}

// A peer that stops reading parks the session writer inside conn.Write; Close has to
// tear the connection down instead of waiting for that writer to finish.
func TestCloseWithBlockedWrite(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- conn
	}()
	client := newClient(t, M.SocksaddrFromNet(listener.Addr()))
	conn, err := client.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"))
	require.NoError(t, err)
	defer conn.Close()

	writing := make(chan struct{})
	go func() {
		close(writing)
		conn.Write(make([]byte, 64*1024*1024))
	}()
	<-writing
	serverConn := <-accepted
	defer serverConn.Close()
	time.Sleep(500 * time.Millisecond)

	closed := make(chan error, 1)
	go func() {
		closed <- client.Close()
	}()
	select {
	case closeErr := <-closed:
		require.NoError(t, closeErr)
	case <-time.After(10 * time.Second):
		require.Fail(t, "Client.Close blocked behind a parked writer")
	}
}

type closingHandler struct{}

func (h closingHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	N.ReportConnHandshakeSuccess(conn, conn)
	time.Sleep(300 * time.Millisecond)
	conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

type burstHandler struct {
	payload []byte
}

func (h burstHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	N.ReportConnHandshakeSuccess(conn, conn)
	conn.Write(h.payload)
	conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

// A frame that is still buffered when the peer's FIN arrives has to survive reads that
// consume it a piece at a time, which is what every bufio-sized consumer does.
func TestReadAfterPeerClose(t *testing.T) {
	t.Parallel()
	payload := make([]byte, 40000)
	for index := range payload {
		payload[index] = byte(index)
	}
	service, err := anytls.NewService(testPassword, anytls.ServiceOptions{
		Handler: burstHandler{payload: payload},
		Logger:  testLogger("svc: "),
	})
	require.NoError(t, err)
	server := startService(t, service)
	client := newClient(t, server)
	conn, err := client.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"))
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)

	received := make([]byte, len(payload))
	for offset := 0; offset < len(received); {
		n, readErr := conn.Read(received[offset:min(offset+512, len(received))])
		require.NoError(t, readErr)
		offset += n
	}
	require.Equal(t, payload, received)
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}

// Every reader parked on a stream has to be released when the peer ends it, not just
// the one that happens to take the wakeup.
func TestParkedReadersWakeOnPeerClose(t *testing.T) {
	t.Parallel()
	service, err := anytls.NewService(testPassword, anytls.ServiceOptions{
		Handler: closingHandler{},
		Logger:  testLogger("svc: "),
	})
	require.NoError(t, err)
	server := startService(t, service)
	client := newClient(t, server)
	conn, err := client.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"))
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)

	const readerCount = 4
	returned := make(chan error, readerCount)
	for range readerCount {
		go func() {
			buffer := make([]byte, 16)
			_, readErr := conn.Read(buffer)
			returned <- readErr
		}()
	}
	for range readerCount {
		select {
		case readErr := <-returned:
			require.Error(t, readErr)
		case <-time.After(10 * time.Second):
			require.Fail(t, "a reader stayed parked after the peer closed the stream")
		}
	}
}
