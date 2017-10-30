# SPythonScanner program
The tutorial found at https://null-byte.wonderhowto.com/how-to/build-stealth-port-scanner-with-scapy-and-python-0164779/ was helpful in the creation of this project.

This scanner is quite simple. It presently only supports the scanning of 1 IP address. It does support multiple ports, as well as UDP and TCP scans. The UDP scans are not very reliable because there is no way to distinguish between open ports and filtered ports. Any none-response is treated as an open port.

The scanner does make an ICMP scan to the host to see if it's up before scanning the ports.
