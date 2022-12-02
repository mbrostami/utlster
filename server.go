package main

import (
	"fmt"
	"net"
)

func listenTcp(ip, port string) error {
	lAddr, _ := net.ResolveTCPAddr("tcp4", ip+":"+port)
	l, err := net.ListenTCP("tcp4", lAddr)
	if err != nil {
		return fmt.Errorf("tcp listen failed: %v", err)
	}
	defer l.Close()
	for {
		newConn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("tcp accept failed: %v", err)
		}
		// Make a buffer to hold incoming data.
		buf := make([]byte, 1024)
		// Read the incoming connection into the buffer.
		_, err = newConn.Read(buf)
		if err != nil {
			return fmt.Errorf("tcp accept read failed: %v", err)
		}
		// Send a response back to person contacting us.
		newConn.Write([]byte("Message received."))
		// Close the connection when you're done with it.
		newConn.Close()
	}
}
