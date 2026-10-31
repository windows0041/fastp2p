package openp2p

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func gatewayTLSConfig(host, caFile string, insecure bool) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	for _, certificate := range []string{rootCA, rootEdgeCA, ISRGRootX1} {
		roots.AppendCertsFromPEM([]byte(certificate))
	}
	if caFile != "" {
		certificate, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read gateway CA: %w", err)
		}
		if !roots.AppendCertsFromPEM(certificate) {
			return nil, fmt.Errorf("gateway CA %q contains no valid PEM certificates", caFile)
		}
	}
	return &tls.Config{
		RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: insecure,
	}, nil
}
