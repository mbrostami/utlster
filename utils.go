package main

import (
	"net"

	"github.com/apparentlymart/go-cidr/cidr"
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
