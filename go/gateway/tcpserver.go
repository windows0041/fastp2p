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
			gLog.Println(LvINFO, "nat tcp:", c.RemoteAddr().String())
			serveTCPProbe(c)
		}(conn)
	}
}

// TCP NAT discovery sends a one-byte marker, not a framed OpenP2P message.
// Reply as soon as bytes arrive so the client can learn its mapped endpoint.
func serveTCPProbe(conn net.Conn) error {
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			if _, writeErr := io.WriteString(conn, conn.RemoteAddr().String()); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			return err
		}
	}
}
