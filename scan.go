package main

import (
	"net"
	"time"
)

const workers = 64
const scanTimeout = 200 * time.Millisecond

type work struct {
	ip   string
	port string
}

type result struct {
	ip   string
	port string
	open bool
}

var workCh chan work
var resCh chan result

// returns opens
func rangePortScan(cidr string, remotePort string) []string {
	workCh = make(chan work, workers)
	resCh = make(chan result, workers)

	for i := 0; i < workers; i++ {
		go worker(workCh, resCh)
	}

	ips := extractIPsFromCIDR(cidr)
	go func() {
		for _, ip := range ips {
			workCh <- work{ip: ip, port: remotePort}
		}
	}()

	var opens []string
	for i := 0; i < len(ips); i++ {
		res := <-resCh
		if res.open {
			opens = append(opens, res.ip)
		}
	}

	return opens
}

func worker(ch chan work, rs chan result) {
	for w := range ch {
		_, err := net.DialTimeout("tcp", w.ip+":"+w.port, scanTimeout)
		rs <- result{
			ip:   w.ip,
			port: w.port,
			open: err == nil,
		}
	}
}
