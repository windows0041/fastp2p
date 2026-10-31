// A test-only peer using the same quic-go version, ALPN and stream framing as
// the Go client. This program is not part of the C library or its executable.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/quic-go/quic-go"
	"io"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		panic("quic-go client|server LOCAL_ADDR PEER_ADDR")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg := &tls.Config{NextProtos: []string{"openp2pv1"}}
	// Match the current Go client's ephemeral 1024-bit peer certificate.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	must(err)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1)},
		&x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	must(err)
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	must(err)
	cfg.Certificates = []tls.Certificate{cert}
	qc := &quic.Config{DisablePathMTUDiscovery: true}
	expected := []byte{8, 0, 0, 0, 4, 0, 2, 0, 255, 254, 253, 252, 251, 250, 249, 248}
	var stream quic.Stream
	if os.Args[1] == "server" {
		listener, err := quic.ListenAddr(os.Args[2], cfg, qc)
		must(err)
		defer listener.Close()
		fmt.Println("GO_QUIC_READY")
		conn, err := listener.Accept(ctx)
		must(err)
		stream, err = conn.AcceptStream(ctx)
		must(err)
		buf := make([]byte, len(expected))
		_, err = io.ReadFull(stream, buf)
		must(err)
		if string(buf) != string(expected) {
			panic("frame mismatch")
		}
		_, err = stream.Write(buf)
		must(err)
		time.Sleep(300 * time.Millisecond)
	} else {
		local, err := net.ResolveUDPAddr("udp", os.Args[2])
		must(err)
		udp, err := net.ListenUDP("udp", local)
		must(err)
		defer udp.Close()
		peer, err := net.ResolveUDPAddr("udp", os.Args[3])
		must(err)
		cfg.InsecureSkipVerify = true
		conn, err := quic.DialContext(ctx, udp, peer, "localhost", cfg, qc)
		must(err)
		stream, err = conn.OpenStreamSync(ctx)
		must(err)
		_, err = stream.Write(expected)
		must(err)
		buf := make([]byte, len(expected))
		_, err = io.ReadFull(stream, buf)
		must(err)
		if string(buf) != string(expected) {
			panic("frame mismatch")
		}
	}
	fmt.Println("GO_QUIC_INTEROP_OK")
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
