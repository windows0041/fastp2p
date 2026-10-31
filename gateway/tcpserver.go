package main

import (
	"io"
	"log"
	"net"
)

func tcpServer(port int) {
	gLog.Println(LvINFO, "ifconfig start at port:", port)
	l, err := net.Listen("tcp", listenAddress(port))
	if err != nil {
		log.Panicln(err)
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Panicln(err)
		}

		go func(c net.Conn) {
			defer c.Close()
			for {
				buf := make([]byte, openP2PHeaderSize)
				_, err := io.ReadFull(c, buf)
				if err != nil {
					return
				}
				gLog.Println(LvINFO, "nat tcp:", c.RemoteAddr().String())
				c.Write([]byte(c.RemoteAddr().String()))
			}
		}(conn)
	}
}
