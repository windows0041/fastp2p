package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type wssSession struct {
	conn                                   *websocket.Conn
	wsMtx                                  sync.Mutex
	requestMtx                             sync.Mutex
	writeCh                                chan []byte
	rspCh                                  chan []byte
	done                                   chan struct{}
	closeOnce                              sync.Once
	mgr                                    *sessionMgr
	node, user                             string
	shareBandWidth                         int
	token, nodeID                          uint64
	natType                                int
	os, lanIP                              string
	hasUPNPorNATPMP, hasIPv4, publicIPPort int
	IPv4, IPv6, mac, version               string
	majorVer                               int
	activeTime, relayTime                  time.Time
	failNodes                              sync.Map
}

var upGrader = websocket.Upgrader{
	ReadBufferSize: 1024, WriteBufferSize: 1024,
	CheckOrigin: func(*http.Request) bool { return true },
}

type sessionMgr struct {
	allSessions    map[uint64]*wssSession
	allSessionsMtx sync.RWMutex
	pushPermission sync.Map
}

func NewSessionMgr() *sessionMgr {
	return &sessionMgr{allSessions: make(map[uint64]*wssSession)}
}

func (mgr *sessionMgr) run() {
	r := gin.New()
	r.Use(gin.Recovery())
	r.GET("/openp2p/v1/login", mgr.handleLogin)
	r.GET("/api/v1/login", mgr.handleLogin)
	server := &http.Server{Addr: listenAddress(gOptions.WSPort), Handler: r,
		ReadHeaderTimeout: 10 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if err := server.ListenAndServeTLS(gOptions.CertFile, gOptions.KeyFile); err != nil {
		log.Fatal(err)
	}
}

func (mgr *sessionMgr) handleLogin(c *gin.Context) {
	node := c.Query("node")
	token, err := strconv.ParseUint(c.Query("token"), 10, 64)
	if len(node) < MinNodeNameLen || len(node) > 31 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "node name must contain 8-31 bytes"})
		return
	}
	if err != nil || token != gToken {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	ws, err := upGrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(1 << 20)
	ipv4, _, err := net.SplitHostPort(ws.RemoteAddr().String())
	if err != nil {
		ws.Close()
		return
	}
	natType, _ := strconv.Atoi(c.Query("nattype"))
	bandwidth, _ := strconv.Atoi(c.Query("sharebandwidth"))
	sess := &wssSession{
		conn: ws, mgr: mgr, node: node, nodeID: nodeNameToID(node), user: gUser, token: token,
		version: c.Query("version"), natType: natType, shareBandWidth: bandwidth,
		IPv4: ipv4, IPv6: c.Query("ipv6"), activeTime: time.Now(), relayTime: time.Now().Add(-24 * time.Hour),
		writeCh: make(chan []byte, 64), rspCh: make(chan []byte, 16), done: make(chan struct{}),
	}
	sess.majorVer = parseMajorVer(sess.version)
	mgr.allSessionsMtx.Lock()
	previous := mgr.allSessions[sess.nodeID]
	mgr.allSessions[sess.nodeID] = sess
	mgr.allSessionsMtx.Unlock()
	if previous != nil {
		previous.close()
	}
	go sess.writeLoop()
	go sess.readLoop()
	sess.write(MsgLogin, 0, &LoginRsp{User: sess.user, Token: sess.token, Node: sess.node, Ts: time.Now().Unix()})
	gLog.Printf(LvINFO, "client login success: %s (%s)", sess.node, sess.version)
}

func (sess *wssSession) writeLoop() {
	defer sess.close()
	for {
		select {
		case <-sess.done:
			return
		case msg := <-sess.writeCh:
			sess.wsMtx.Lock()
			sess.conn.SetWriteDeadline(time.Now().Add(ClientAPITimeout))
			err := sess.conn.WriteMessage(websocket.BinaryMessage, msg)
			sess.wsMtx.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (sess *wssSession) readLoop() {
	defer sess.close()
	for {
		sess.conn.SetReadDeadline(time.Now().Add(NetworkHeartbeatTime + 10*time.Second))
		kind, msg, err := sess.conn.ReadMessage()
		if err != nil {
			return
		}
		if kind == websocket.BinaryMessage {
			select {
			case MsgQueue <- &msgContext{sess: sess, msg: msg}:
			case <-sess.done:
				return
			}
		}
	}
}

func (sess *wssSession) close() error {
	sess.closeOnce.Do(func() {
		close(sess.done)
		sess.conn.Close()
		sess.mgr.allSessionsMtx.Lock()
		if sess.mgr.allSessions[sess.nodeID] == sess {
			delete(sess.mgr.allSessions, sess.nodeID)
			sess.mgr.pushPermission.Range(func(key, _ interface{}) bool {
				pair := key.(pushPair)
				if pair.from == sess.nodeID || pair.to == sess.nodeID {
					sess.mgr.pushPermission.Delete(key)
				}
				return true
			})
		}
		sess.mgr.allSessionsMtx.Unlock()
	})
	return nil
}

func (sess *wssSession) write(mainType uint16, subType uint16, packet interface{}) error {
	msg, err := newMessage(mainType, subType, packet)
	if err != nil {
		return err
	}
	return sess.writeBuff(msg)
}

func (sess *wssSession) writeSync(mainType uint16, subType uint16, packet interface{}) error {
	msg, err := newMessage(mainType, subType, packet)
	if err != nil {
		return err
	}
	sess.wsMtx.Lock()
	defer sess.wsMtx.Unlock()
	sess.conn.SetWriteDeadline(time.Now().Add(ClientAPITimeout))
	return sess.conn.WriteMessage(websocket.BinaryMessage, msg)
}

func (sess *wssSession) writeBuff(buff []byte) error {
	select {
	case <-sess.done:
		return errors.New("session closed")
	default:
	}
	select {
	case <-sess.done:
		return errors.New("session closed")
	case sess.writeCh <- buff:
		return nil
	default:
		return fmt.Errorf("write queue full for %s", sess.node)
	}
}
