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
var flagOnce bool
var flagOneToAll bool
var flagV bool

// TODO option to repeat sending packets based on pcap

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	flag.BoolVar(&flagTest, "test", false, "runs a local server and connects to that - remote ip will be ignored")
	flag.StringVar(&flagSNI, "sni", "", "custom SNI")
	flag.StringVar(&flagPcap, "p", "", "PCAP file to extract client hellos")
	flag.StringVar(&flagRawClientHello, "r", "", "Raw client hello as HEX stream")
	flag.StringVar(&flagRemoteIP, "remote-ip", "127.0.0.1", "remote ip")
	flag.StringVar(&flagCIDR, "cidr", "", "scan cidr with port 443 and use IPs as remote-ip - remote ip option will be ignored")
	flag.StringVar(&flagRemotePort, "remote-port", "443", "remote port")
	flag.BoolVar(&flagOnce, "once", false, "only one handshake to one remote")
	flag.BoolVar(&flagOneToAll, "one-to-all", false, "only one handshake to all the remotes")
	flag.BoolVar(&flagV, "v", false, "verbosity")
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
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

	if flagRemoteIP == "" && flagCIDR == "" {
		flag.Usage()
		log.Fatal().Msg("remote-ip or cidr is required")
	}

	clientHellos := make([][]byte, 0)

	if flagRawClientHello != "" {
		log.Debug().Msg("decoding client hello from input")
		rawCapturedClientHelloBytes, err := hex.DecodeString(flagRawClientHello)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
		if !isClientHello(rawCapturedClientHelloBytes) {
			log.Fatal().Msg("given raw client hello is not valid!")
		}
		clientHellos = append(clientHellos, rawCapturedClientHelloBytes)
	}

	if flagPcap != "" {
		log.Debug().Msg("parsing the pcap file to extract client helloes ... ")
		var err error
		clientHellos, err = extractClientHellos(flagPcap)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
		if len(clientHellos) == 0 {
			log.Fatal().Msg("client hello not found")
		}
		log.Debug().Msgf("%d client hello found", len(clientHellos))
	}

	if flagTest {
		flagRemoteIP = "127.0.0.1"
		if err := listenTLS(flagRemoteIP, flagRemotePort); err != nil {
			log.Fatal().Err(err).Send()
		}
	}

	remoteIPs := []string{flagRemoteIP}

	if flagCIDR != "" && !flagTest {
		remoteIPs = rangeScanTLSPort(flagCIDR, flagRemotePort)
		log.Debug().Msgf("total %d ip found", len(remoteIPs))
	}

NextIP:
	for _, rip := range remoteIPs {
		rAddr, _ := net.ResolveTCPAddr("tcp", rip+":"+flagRemotePort)
		i := 0
		for _, clientHello := range clientHellos {
			i++
			log.Debug().Msgf("starting tls handshake %d to %s", i, rAddr.String())
			if err := handshake(rAddr, flagSNI, clientHello); err != nil {
				log.Error().Err(err).Send()
				if errors.Is(err, errTCPConn) {
					continue NextIP
				}
			}

			if flagOnce {
				return
			}

			if flagOneToAll {
				break
			}
		}
	}
}
