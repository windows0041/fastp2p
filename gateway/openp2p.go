package main

import (
	"log"
	"math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"time"
)

var (
	gWSSessionMgr *sessionMgr
	gHandler      *msgHandler
	gToken        uint64
	gUser         string
	gPassword     string
)

func main() {
	if err := parseParams(); err != nil {
		log.Fatal(err)
	}
	gLog = NewLogger(filepath.Dir(os.Args[0]), "openp2p", LvINFO, 1*1024*1024, LogFileAndConsole)
	rand.Seed(time.Now().UnixNano())
	if gOptions.PprofAddress != "" {
		go func() { log.Println(http.ListenAndServe(gOptions.PprofAddress, nil)) }()
	}
	gHandler = &msgHandler{
		handlers: make(map[uint16]handlerInterface),
	}
	login := loginHandler{}
	gHandler.registerHandler(MsgLogin, &login)
	gHandler.registerHandler(MsgHeartbeat, &login)
	gHandler.registerHandler(MsgPush, &pushHandler{})
	gHandler.registerHandler(MsgRelay, &relayHandler{})
	gHandler.registerHandler(MsgReport, &reportHandler{})
	gHandler.registerHandler(MsgQuery, &queryHandler{})
	gHandler.registerHandler(MsgSDWAN, &sdwanHandler{})
	nat := natHandler{}
	gHandler.registerHandler(MsgNATDetect, &nat)
	for i := 0; i < 16; i++ {
		go gHandler.handleMessage()
	}
	initStun()
	gWSSessionMgr = NewSessionMgr()
	go gWSSessionMgr.run()
	if err := runWeb(); err != nil {
		log.Fatal(err)
	}
}

func initStun() {
	go tcpServer(IfconfigPort1)
	go tcpServer(IfconfigPort2)
	for _, port := range []int{IfconfigPort1, IfconfigPort2, UDPPort1, UDPPort2} {
		if _, err := newUDPServer(&net.UDPAddr{IP: net.ParseIP(gOptions.BindHost), Port: port}); err != nil {
			log.Fatalf("listen UDP %d: %v", port, err)
		}
	}
	gLog.Printf(LvINFO, "NAT service: TCP 27180-27181, UDP 27180-27183")
}
