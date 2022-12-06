package main

import (
	"bufio"
	"fmt"
	"net"
	"os"

	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/rs/zerolog/log"
)

func extractIPsFromCIDR(ipRange string) []string {
	_, IPNet, _ := net.ParseCIDR(ipRange)
	f, l := cidr.AddressRange(IPNet)

	var rng []string
	for i := f; !i.Equal(l); i = cidr.Inc(i) {
		if i.IsMulticast() || i.IsUnspecified() {
			continue
		}
		rng = append(rng, i.String())
	}

	return rng
}

func readIPFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	invalid := 0
	for scanner.Scan() {
		ip, err := net.ResolveIPAddr("ip", scanner.Text())
		if err != nil {
			invalid++
			log.Debug().Msgf("failed to parse IP %s: %v", scanner.Text(), err)
		}
		lines = append(lines, ip.String())
	}

	if invalid > 0 {
		return lines, fmt.Errorf("total %d ip are invalid", invalid)
	}

	return lines, scanner.Err()
}
