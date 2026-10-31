package openp2p

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGatewayTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, host, ca string
		success        bool
	}{
		{"custom CA", "127.0.0.1", caFile, true},
		{"untrusted CA", "127.0.0.1", "", false},
		{"wrong hostname", "wrong.example", caFile, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config, err := gatewayTLSConfig(tt.host, tt.ca, false)
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: config}, Timeout: 3 * time.Second}
			defer client.CloseIdleConnections()
			response, err := client.Get(server.URL)
			if response != nil {
				response.Body.Close()
			}
			if (err == nil) != tt.success {
				t.Fatalf("TLS request error=%v; expected success=%t", err, tt.success)
			}
		})
	}
}

func TestGatewayTLSInvalidCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-ca.pem")
	if _, err := gatewayTLSConfig("localhost", path, false); err == nil {
		t.Fatal("missing CA accepted")
	}
	if err := os.WriteFile(path, []byte("not a PEM certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := gatewayTLSConfig("localhost", path, false); err == nil {
		t.Fatal("invalid CA accepted")
	}
}
