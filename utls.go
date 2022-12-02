package main

import (
	"fmt"
	"net"

	tls "github.com/refraction-networking/utls"
)

func handshake(conn net.Conn, clientHello []byte) error {
	uConn := tls.UClient(conn, &tls.Config{InsecureSkipVerify: true}, tls.HelloCustom)
	defer uConn.Close()

	fingerprinter := &tls.Fingerprinter{}
	generatedSpec, err := fingerprinter.FingerprintClientHello(clientHello)

	if err != nil {
		return fmt.Errorf("fingerprinting failed: %v", err)
	}
	if err := uConn.ApplyPreset(generatedSpec); err != nil {
		return fmt.Errorf("applying generated spec failed: %v", err)
	}
	// uConn.SetSNI("google.com")
	if err := uConn.Handshake(); err != nil {
		return fmt.Errorf("handshake failed: %v", err)
	}

	return nil
}
