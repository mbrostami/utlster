package main

import (
	"crypto/md5"

	"github.com/dreadl0ck/ja3"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	tls "github.com/refraction-networking/utls"
)

type ClientHello struct {
	Raw []byte
	JA3 [md5.Size]byte
}

func ExtractClientHellos(file string) ([]ClientHello, error) {
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeStreamsAsDatagrams = true
	clientHellos := make([]ClientHello, 0)

	for packet := range packetSource.Packets() {
		if tcpLayer, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
			if IsClientHello(tcpLayer.Payload) {
				clientHellos = append(clientHellos, ClientHello{
					Raw: tcpLayer.Payload,
					JA3: ja3.DigestPacket(packet),
				})
			}
		}
	}

	return clientHellos, nil
}

func IsClientHello(data []byte) bool {
	fingerPrinter := &tls.Fingerprinter{}
	_, err := fingerPrinter.FingerprintClientHello(data)
	return err == nil
}

// 0x16 0x03 X Y Z 0x01 A B C
// A = 0 and 256*X+Y = 256*B+C+4.
func isClientHelloByteCheck(payload []byte) bool {
	if payload[0] == 0x16 &&
		payload[1] == 0x03 &&
		payload[5] == 0x01 &&
		payload[6] == 0x00 &&
		0xfd*payload[2]+payload[3] == 0xff*payload[7]+payload[8]+0x04 {
		return true
	}
	return false
}
