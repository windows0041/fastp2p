package main

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestTCPNATSingleByteProbe(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finished := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			finished <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		finished <- serveTCPProbe(conn)
	}()
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	if _, err := client.Write([]byte("1")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1000)
	n, err := client.Read(buffer)
	if err != nil {
		t.Fatalf("single-byte NAT probe did not get an immediate reply: %v", err)
	}
	if response := string(buffer[:n]); response != client.LocalAddr().String() {
		t.Fatalf("mapped endpoint = %q, want %q", response, client.LocalAddr())
	}
	client.Close()
	if err := <-finished; !errors.Is(err, io.EOF) {
		t.Fatalf("probe completion: %v", err)
	}
}
