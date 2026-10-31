package openp2p

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDialTCP(t *testing.T) {
	InitForUnitTest(LvDEBUG)
	for _, tt := range []struct {
		name    string
		network string
		address string
		mode    string
	}{
		{"IPv4", "tcp4", "127.0.0.1:0", LinkModeTCP4},
		{"IPv6", "tcp6", "[::1]:0", LinkModeTCP6},
	} {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.ListenTCP(tt.network, mustResolveTCPAddr(t, tt.network, tt.address))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			listener.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("openp2p loopback handshake")
			serverResult := make(chan error, 1)
			go func() {
				serverResult <- echoTCPHandshake(listener, payload)
			}()

			addr := listener.Addr().(*net.TCPAddr)
			client, err := dialTCP(addr.IP.String(), addr.Port, 0, tt.mode)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetReadDeadline(time.Now().Add(5 * time.Second))
			if err := client.WriteBytes(MsgP2P, MsgTunnelHandshake, payload); err != nil {
				t.Fatal(err)
			}
			head, body, err := client.ReadBuffer()
			if err != nil {
				t.Fatal(err)
			}
			if head.MainType != MsgP2P || head.SubType != MsgTunnelHandshakeAck || !bytes.Equal(body, payload) {
				t.Fatalf("unexpected handshake response: header=%+v body=%q", head, body)
			}
			if err := <-serverResult; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func mustResolveTCPAddr(t *testing.T, network, address string) *net.TCPAddr {
	t.Helper()
	addr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func echoTCPHandshake(listener *net.TCPListener, payload []byte) error {
	conn, err := listener.AcceptTCP()
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	server := &underlayTCP{writeMtx: &sync.Mutex{}, Conn: conn}
	head, body, err := server.ReadBuffer()
	if err != nil {
		return err
	}
	if head.MainType != MsgP2P || head.SubType != MsgTunnelHandshake || !bytes.Equal(body, payload) {
		return fmt.Errorf("unexpected handshake request: header=%+v body=%q", head, body)
	}
	return server.WriteBytes(MsgP2P, MsgTunnelHandshakeAck, body)
}
