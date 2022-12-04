package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func extractClientHellos(file string) ([][]byte, error) {
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	clientHellos := make([][]byte, 0)
	for packet := range packetSource.Packets() {

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			payload := tcpLayer.LayerPayload()
			if len(payload) < 9 {
				continue
			}
			if isClientHello(payload) {
				clientHellos = append(clientHellos, payload)
			}
		}
	}

	return clientHellos, nil
}

// 0x16 0x03 X Y Z 0x01 A B C
// A = 0 and 256*X+Y = 256*B+C+4.
func isClientHello(payload []byte) bool {
	if payload[0] == 0x16 &&
		payload[1] == 0x03 &&
		payload[5] == 0x01 &&
		payload[6] == 0x00 &&
		0xfd*payload[2]+payload[3] == 0xff*payload[7]+payload[8]+0x04 {
		return true
	}
	return false
}
