package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"net"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var flagTest bool
var flagRemoteIP string
var flagCIDR string
var flagRemotePort string
var flagSNI string
var flagPcap string
var flagRawClientHello string
var flagRemoteIPList string
var flagOnce bool
var flagOneToAll bool
var flagV bool

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	flag.BoolVar(&flagTest, "test", false, "runs a local server and connects to that - remote ip will be ignored")
	flag.StringVar(&flagSNI, "sni", "", "custom SNI")
	flag.StringVar(&flagPcap, "p", "", "PCAP file to extract client hellos")
	flag.StringVar(&flagRawClientHello, "r", "", "Raw client hello as HEX stream")
	flag.StringVar(&flagRemoteIP, "remote-ip", "", "remote ip")
	flag.StringVar(&flagRemoteIPList, "remote-ip-list", "", "path to a file containing remote ip addresses (one ip per line)")
	flag.StringVar(&flagCIDR, "cidr", "", "scan cidr with remote port and use IPs as remote-ip")
	flag.StringVar(&flagRemotePort, "remote-port", "443", "remote port")
	flag.BoolVar(&flagOnce, "once", false, "only one handshake to one remote")
	flag.BoolVar(&flagOneToAll, "one-to-all", false, "only one handshake to all the remotes")
	flag.BoolVar(&flagV, "v", false, "verbosity")
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if flagV {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	if flagPcap == "" && flagRawClientHello == "" {
		flag.Usage()
		log.Fatal().Msg("pcap or raw should be specifed")
	}

	if flagRemotePort == "" {
		flag.Usage()
		log.Fatal().Msg("remote-ip or cidr and remote-port are required")
	}

	if flagTest {
		flagRemoteIP = "127.0.0.1"
		if err := listenTLS(flagRemoteIP, flagRemotePort); err != nil {
			log.Fatal().Err(err).Send()
		}
	}

	if flagRemoteIP == "" && flagCIDR == "" && flagRemoteIPList == "" {
		flag.Usage()
		log.Fatal().Msg("remote-ip or cidr or remote-ip-list is required")
	}

	clientHellos := make([]ClientHello, 0)

	if flagRawClientHello != "" {
		log.Info().Msg("decoding client hello from input")
		rawCapturedClientHelloBytes, err := hex.DecodeString(flagRawClientHello)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
		if !IsClientHello(rawCapturedClientHelloBytes) {
			log.Fatal().Msg("given raw client hello is not valid!")
		}
		clientHellos = append(clientHellos, ClientHello{
			Raw: rawCapturedClientHelloBytes,
		})
	}

	if flagPcap != "" {
		log.Info().Msg("parsing the pcap file to extract client helloes ... ")
		var err error
		clientHellos, err = ExtractClientHellos(flagPcap)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
		if len(clientHellos) == 0 {
			log.Fatal().Msg("client hello not found")
		}
		log.Info().Msgf("%d client hello found", len(clientHellos))
	}

	remoteIPs := make([]string, 0)

	if flagRemoteIP != "" {
		remoteIPs = append(remoteIPs, flagRemoteIP)
	}

	if flagCIDR != "" && !flagTest {
		remoteIPs = append(remoteIPs, rangePortScan(flagCIDR, flagRemotePort)...)
		log.Info().Msgf("total %d ip found", len(remoteIPs))
	}

	if flagRemoteIPList != "" && !flagTest {
		ips, err := readIPFile(flagRemoteIPList)
		if err != nil {
			log.Error().Err(err).Send()
		}
		log.Info().Msgf("parsed %d ips from file", len(ips))
		remoteIPs = append(remoteIPs, ips...)
	}

NextIP:
	for _, rip := range remoteIPs {
		rAddr, _ := net.ResolveTCPAddr("tcp", rip+":"+flagRemotePort)
		i := 0
		for _, clientHello := range clientHellos {
			i++
			log.Info().Msgf("%d: starting tls handshake %x to %s", i, clientHello.JA3[:], rAddr.String())
			if err := handshake(rAddr, flagSNI, clientHello); err != nil {
				log.Error().Err(err).Send()
				if errors.Is(err, errTCPConn) {
					continue NextIP
				}
			}
			log.Info().Msg("handshake done!")

			if flagOnce {
				return
			}

			if flagOneToAll {
				break
			}
		}
	}
}
