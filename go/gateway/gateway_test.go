package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	gUser, gPassword, JWTSecret = "local-test-user", "local-test-password", "local-test-jwt-secret"
	gToken = 123456789
	gWSSessionMgr = NewSessionMgr()
	gOptions.SDWAN = SDWANInfo{TunnelNum: 2, Mtu: 1420}
	dir, err := os.MkdirTemp("", "openp2p-gateway-tests-")
	if err != nil {
		panic(err)
	}
	gLog = NewLogger(dir, "gateway-test", LvERROR, 1024*1024, LogConsole)
	os.Exit(m.Run())
}

func TestManagementAuthentication(t *testing.T) {
	router := newWebRouter()
	for _, path := range []string{"/api/v1/devices", "/api/v1/device/test-node/restart"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s without auth: status %d", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	login, _ := json.Marshal(ProfileInfo{User: gUser, Password: gPassword})
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/user/login", bytes.NewReader(login)))
	if response.Code != http.StatusOK {
		t.Fatalf("login status %d", response.Code)
	}
	var credentials struct {
		Token     string
		NodeToken string
	}
	if err := json.Unmarshal(response.Body.Bytes(), &credentials); err != nil {
		t.Fatal(err)
	}
	if credentials.NodeToken != "123456789" {
		t.Fatal("wrong installation token")
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	request.Header.Set("Authorization", credentials.Token)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated request status %d", response.Code)
	}
}

func TestHeartbeatTimestamp(t *testing.T) {
	sess := &wssSession{writeCh: make(chan []byte, 1), done: make(chan struct{})}
	message, _ := newMessage(MsgHeartbeat, 0, "")
	if err := (&loginHandler{}).handleMessage(&msgContext{sess: sess, msg: message}); err != nil {
		t.Fatal(err)
	}
	reply := <-sess.writeCh
	if len(reply) != openP2PHeaderSize+8 {
		t.Fatalf("heartbeat has %d bytes", len(reply))
	}
	timestamp := int64(binary.LittleEndian.Uint64(reply[openP2PHeaderSize:]))
	if delta := time.Since(time.Unix(0, timestamp)); delta < 0 || delta > time.Second {
		t.Fatalf("invalid server timestamp %d", timestamp)
	}
}

func TestReportBasicAcknowledgement(t *testing.T) {
	sess := &wssSession{writeCh: make(chan []byte, 1), done: make(chan struct{})}
	message, _ := newMessage(MsgReport, MsgReportBasic, ReportBasic{LanIP: "127.0.0.1", Version: "3.25.11", PublicIPPort: 23001})
	if err := (&reportHandler{}).handleMessage(&msgContext{sess: sess, msg: message}); err != nil {
		t.Fatal(err)
	}
	header, err := decodeHeader(<-sess.writeCh)
	if err != nil || header.MainType != MsgReport || header.SubType != MsgReportBasicRsp {
		t.Fatalf("invalid acknowledgement: %+v %v", header, err)
	}
	if sess.publicIPPort != 23001 {
		t.Fatal("public listen port not recorded")
	}
}

func TestSDWANConfiguration(t *testing.T) {
	info := SDWANInfo{Enable: 1, Gateway: "10.80.0.254/24", Mode: "fullmesh", TunnelNum: 2, Mtu: 1420,
		Nodes: []*SDWANNode{{Name: "test-node-a", IP: "10.80.0.1"}, {Name: "test-node-b", IP: "10.80.0.2"}}}
	if err := validateSDWAN(info); err != nil {
		t.Fatal(err)
	}
	info.Nodes[1].IP = "10.80.0.1"
	if err := validateSDWAN(info); err == nil {
		t.Fatal("duplicate IP accepted")
	}
}

func TestMultiplePushPeers(t *testing.T) {
	mgr := NewSessionMgr()
	mgr.grantPush(1, 2)
	mgr.grantPush(1, 3)
	for _, pair := range []pushPair{{1, 2}, {2, 1}, {1, 3}, {3, 1}} {
		if _, ok := mgr.pushPermission.Load(pair); !ok {
			t.Fatalf("missing permission for %+v", pair)
		}
	}
	if _, ok := mgr.pushPermission.Load(pushPair{2, 3}); ok {
		t.Fatal("permission granted to an unrelated pair")
	}
}
