package workcontext

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/test/bufconn"
)

// Only the raw socket is replaced: the SDK's TLS dialer, crypto/tls, HTTP
// transport and server all run normally. Buffered connections let a TLS alert
// cross an in-flight handshake write, just as a socket does, without requiring
// permission to bind a loopback port. bufconn is an existing test dependency.
var mintMemoryNetwork sync.Map
var mintMemoryPorts atomic.Uint64

type mintMemoryListener struct {
	*bufconn.Listener
	address net.Addr
	once    sync.Once
}

func newMintMemoryListener(t *testing.T) *mintMemoryListener {
	t.Helper()
	listener := &mintMemoryListener{Listener: bufconn.Listen(256 * 1024), address: mintMemoryAddress()}
	mintMemoryNetwork.Store(listener.address.String(), listener)
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func mintMemoryAddress() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10000 + int(mintMemoryPorts.Add(1))}
}

func (l *mintMemoryListener) Addr() net.Addr { return l.address }

func (l *mintMemoryListener) Close() error {
	l.once.Do(func() {
		mintMemoryNetwork.Delete(l.address.String())
		_ = l.Listener.Close()
	})
	return nil
}

func (l *mintMemoryListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &mintMemoryConnection{Conn: connection, local: l.address, remote: mintMemoryAddress()}, nil
}

type mintMemoryConnection struct {
	net.Conn
	local, remote net.Addr
}

func (c *mintMemoryConnection) LocalAddr() net.Addr  { return c.local }
func (c *mintMemoryConnection) RemoteAddr() net.Addr { return c.remote }

func dialMintMemory(ctx context.Context, _, address string) (net.Conn, error) {
	entry, ok := mintMemoryNetwork.Load(address)
	if !ok {
		return nil, net.ErrClosed
	}
	listener := entry.(*mintMemoryListener)
	return listener.Listener.DialContext(ctx)
}

func useMintMemoryNetwork(t *testing.T, client *MintClient) {
	t.Helper()
	transport, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	transport.DialContext = dialMintMemory
}
