# utlster
```
Usage of utlster
  -cidr string
        scan cidr with port 443 and use IPs as remote-ip - remote ip option will be ignored
  -once
        only one handshake to one remote
  -one-to-all
        only one handshake to all the remotes
  -p string
        PCAP file to extract client hellos
  -r string
        Raw client hello as HEX stream
  -remote-ip string
        remote ip
  -remote-ip-list string
        path to a file containing remote ip addresses (one ip per line)
  -remote-port string
        remote port (default "443")
  -sni string
        custom SNI
  -test
        runs a local server and connects to that - remote ip will be ignored
  -v    verbosity
```