package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
)

type gatewayOptions struct {
	CertFile, KeyFile, BindHost, PprofAddress, SDWANFile string
	APIPort, WSPort                                      int
	SDWAN                                                SDWANInfo
}

var gOptions gatewayOptions

func parseParams() error {
	flag.StringVar(&gOptions.CertFile, "cert", envDefault("OPENP2P_TLS_CERT", "api.crt"), "TLS certificate chain in PEM format")
	flag.StringVar(&gOptions.KeyFile, "key", envDefault("OPENP2P_TLS_KEY", "api.key"), "TLS private key in PEM format")
	flag.StringVar(&gOptions.BindHost, "bind", "", "IP address to listen on; empty listens on all interfaces")
	flag.IntVar(&gOptions.APIPort, "apiport", 10008, "HTTPS management API port")
	flag.IntVar(&gOptions.WSPort, "port", WsPort, "WSS client login port")
	flag.StringVar(&gOptions.PprofAddress, "pprof", "", "optional debug HTTP address, e.g. 127.0.0.1:6060")
	flag.StringVar(&gOptions.SDWANFile, "sdwan-config", "", "optional SD-WAN JSON configuration file")
	flag.Parse()
	if gOptions.BindHost != "" && net.ParseIP(gOptions.BindHost) == nil {
		return fmt.Errorf("-bind must be an IP address")
	}
	if _, err := tls.LoadX509KeyPair(gOptions.CertFile, gOptions.KeyFile); err != nil {
		return fmt.Errorf("load gateway TLS certificate: %w", err)
	}
	gUser, gPassword = os.Getenv("OPENP2P_USER"), os.Getenv("OPENP2P_PASSWORD")
	if gUser == "" || gPassword == "" {
		return ErrUserOrPwdNotSet
	}
	gToken = nodeNameToID(gUser + gPassword)
	if token := os.Getenv("OPENP2P_TOKEN"); token != "" {
		value, err := strconv.ParseUint(token, 10, 64)
		if err != nil || value == 0 {
			return fmt.Errorf("OPENP2P_TOKEN must be a nonzero uint64")
		}
		gToken = value
	}
	JWTSecret = gUser + gPassword + "@openp2p.cn"
	gOptions.SDWAN = SDWANInfo{TunnelNum: 2, Mtu: 1420}
	if gOptions.SDWANFile != "" {
		data, err := os.ReadFile(gOptions.SDWANFile)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &gOptions.SDWAN); err != nil {
			return err
		}
		if err := validateSDWAN(gOptions.SDWAN); err != nil {
			return err
		}
	}
	return nil
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func listenAddress(port int) string {
	return net.JoinHostPort(gOptions.BindHost, strconv.Itoa(port))
}
