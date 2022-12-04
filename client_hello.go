package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	tls "github.com/refraction-networking/utls"
	"github.com/rs/zerolog/log"
)

func extractClientHellos(file string) ([][]byte, error) {
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.SkipDecodeRecovery = true
	packetSource.DecodeStreamsAsDatagrams = true
	clientHellos := make([][]byte, 0)
	for packet := range packetSource.Packets() {
		tlsLayer := packet.Layer(layers.LayerTypeTLS)
		if tlsLayer == nil {
			continue
		}

		layer, ok := tlsLayer.(*layers.TLS)
		if !ok {
			continue
		}

		if len(layer.Handshake) == 0 {
			continue
		}

		if layer.Handshake[0].TLSRecordHeader.ContentType == layers.TLSHandshake &&
			isClientHello(layer.Contents) {
			clientHellos = append(clientHellos, layer.Contents)
		}
	}

	return clientHellos, nil
}

func isClientHello(data []byte) bool {
	fingerPrinter := &tls.Fingerprinter{}
	generatedSpec, err := fingerPrinter.FingerprintClientHello(data)
	if err != nil {
		return false
	}
	log.Debug().Msgf("found client hello: %+v", generatedSpec)
	return true
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
