package test

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	anytls "github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	upstream "github.com/anytls/sing-anytls"
	upstreampadding "github.com/anytls/sing-anytls/padding"
	"github.com/stretchr/testify/require"
)

const testPassword = "b0d4b1de-9b06-4c9c-a0b6-4c4a5f6a7e5f"

var customPaddingScheme = []byte(`stop=6
0=64-96
1=200-600
2=300-700,c,400-900
3=100-200
4=1200-1400
5=64-64`)

var oversizedPaddingRecords = []byte(`stop=5
0=30-30
1=70000-70000,140000-140000
2=70000-70000
3=9-9,70000-70000
4=100-200`)

func unsendablePaddingScheme() []byte {
	var builder strings.Builder
	builder.WriteString("stop=8")
	for packet := range 8000 {
		builder.WriteString("\n")
		builder.WriteString(strconv.Itoa(packet))
		builder.WriteString("=500-1000")
	}
	return []byte(builder.String())
}

type connectionService interface {
	NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error
}

type proxyHandler struct{}

func (h proxyHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	remote, err := net.Dial(N.NetworkTCP, destination.String())
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	err = N.ReportConnHandshakeSuccess(conn, remote)
	if err != nil {
		remote.Close()
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	bufio.CopyConn(ctx, conn, remote)
	if onClose != nil {
		onClose(nil)
	}
}

type echoHandler struct{}

func (h echoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	conn.Write([]byte("fallback"))
	io.Copy(io.Discard, conn)
	if onClose != nil {
		onClose(nil)
	}
}

func startTCPEcho(t *testing.T) M.Socksaddr {
	listener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		listener.Close()
	})
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				io.Copy(conn, conn)
				conn.Close()
			}()
		}
	}()
	return M.SocksaddrFromNet(listener.Addr())
}

func startService(t *testing.T, service connectionService) M.Socksaddr {
	listener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		listener.Close()
	})
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				serveErr := service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
				if serveErr != nil {
					testLogger("svc: ").Error("new connection: ", serveErr)
				}
			}()
		}
	}()
	return M.SocksaddrFromNet(listener.Addr())
}

func newService(t *testing.T, paddingScheme []byte, fallback N.TCPConnectionHandlerEx) *anytls.Service {
	service, err := anytls.NewService(testPassword, anytls.ServiceOptions{
		PaddingScheme:   paddingScheme,
		Handler:         proxyHandler{},
		FallbackHandler: fallback,
		Logger:          testLogger("svc: "),
	})
	require.NoError(t, err)
	return service
}

func newMultiService(t *testing.T) *anytls.MultiService[string] {
	service, err := anytls.NewMultiService[string](anytls.ServiceOptions{
		Handler: proxyHandler{},
		Logger:  testLogger("svc: "),
	})
	require.NoError(t, err)
	require.NoError(t, service.UpdateUsers([]string{"alice", "bob"}, []string{"other-password", testPassword}))
	return service
}

func closedPort(t *testing.T) M.Socksaddr {
	listener, err := net.Listen(N.NetworkTCP, "127.0.0.1:0")
	require.NoError(t, err)
	address := M.SocksaddrFromNet(listener.Addr())
	listener.Close()
	return address
}

func newClient(t *testing.T, server M.Socksaddr) *anytls.Client {
	client, err := anytls.NewClient(anytls.ClientOptions{
		Password: testPassword,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			return net.Dial(N.NetworkTCP, server.String())
		},
		Logger: testLogger("svc: "),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Close()
	})
	return client
}

func newUpstreamService(t *testing.T, paddingScheme []byte) *upstream.Service {
	if len(paddingScheme) == 0 {
		paddingScheme = upstreampadding.DefaultPaddingScheme
	}
	service, err := upstream.NewService(upstream.ServiceConfig{
		Users:         []upstream.User{{Name: "test", Password: testPassword}},
		PaddingScheme: paddingScheme,
		Handler:       proxyHandler{},
		Logger:        testLogger("svc: "),
	})
	require.NoError(t, err)
	return service
}

func newUpstreamClient(t *testing.T, server M.Socksaddr) *upstream.Client {
	client, err := upstream.NewClient(context.Background(), upstream.ClientConfig{
		Password: testPassword,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			return net.Dial(N.NetworkTCP, server.String())
		},
		Logger: testLogger("svc: "),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Close()
	})
	return client
}
