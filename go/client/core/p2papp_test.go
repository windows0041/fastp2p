package openp2p

import (
	"net"
	"testing"
)

func TestUDPListenerLocalWhitelist(t *testing.T) {
	InitForUnitTest(LvERROR)
	app := &p2pApp{config: AppConfig{Whitelist: "127.0.0.1"}}
	// A stopped app still creates and closes the real listener, without starting
	// tunnel work. LocalAddr retains the address selected by the operating system.
	if err := app.listenUDP(); err != nil {
		t.Fatal(err)
	}
	address := app.listenerUDP.LocalAddr().(*net.UDPAddr)
	if !address.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("local whitelist exposed UDP listener on %s", address)
	}
}
