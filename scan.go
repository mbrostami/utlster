package main

import (
	"net"
	"sync"
	"time"
)

// TODO
func rangeScanTLSPort(workers int) {
	var wg *sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			scanner("")
			wg.Done()
		}()
	}
	wg.Wait()

}

func scanner(ip string) bool {
	_, err := net.DialTimeout("tcp", ip, time.Duration(300)*time.Millisecond)
	return err == nil
}
