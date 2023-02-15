# Utlster

Utlster is a command-line application that allows you to perform custom TLS handshakes with remote servers using extracted client hellos (fingerprints) from PCAP files. It uses the `utls` library to establish connections with TLS servers.  


It can perform customized handshakes with specific SNI values and multiple remote IP addresses. You can choose to perform a handshake with all IP addresses in a given CIDR range that has open 443 port, one remote IP address, or multiple remote IP addresses. It also supports running a local server for testing purposes. You can also specify the path to a PCAP file containing client hellos or a raw client hello as a hexadecimal string to use for the handshake.  



## Docker 

Test with an example:  
```
docker run -it --rm --name utlster mbrostamih/utlster:latest -v -test -p /example/telegram.pcap
```

## Usage

The behavior of Utlster can be controlled by various command-line arguments:

`-cidr`: Perform handshake with all IP addresses in a given CIDR range that have port 443 open.   
`-once`: Perform one handshake to a single remote IP address.   
`-one-to-all`: Perform one handshake to all remote IP addresses.   
`-p`: Specifies the path to a PCAP file containing client hellos to use for the handshake.  
`-r`: Specifies a raw client hello as a hexadecimal string to use for the handshake.  
`-remote-ip`: Specifies the remote IP address to perform the handshake.  
`-remote-ip-list`: Specifies the path to a file containing remote IP addresses (one IP per line) to perform the handshake with.  
`-remote-port`: Specifies the port number of the remote server, default is set to "443".  
`-sni`: Specifies a custom SNI value to use during the handshake.  
`-test`: Run a local server and connect to that - remote IP will be ignored.  
`-v`: Increase the verbosity level of the output.  
