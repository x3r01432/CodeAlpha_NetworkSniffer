# CodeAlpha_NetworkSniffer
Basic network sniffer in Python with `scapy` (CodeAlpha Cyber Security, Task 1).

It captures live packets and shows source/destination IPs, protocol (TCP, UDP, DNS, ICMP), ports, TCP flags, and a printable payload preview, then a per-protocol summary.

## Run
```
pip install -r requirements.txt
sudo python3 sniffer.py -c 20
sudo python3 sniffer.py -f "udp port 53"   # DNS only
```
Use it only on networks you own or are allowed to monitor.

## How data flows
Each packet is layered: Ethernet frame, then the IP header (who to who), then the transport header (TCP/UDP ports), then the application payload. The sniffer peels these layers to show each one.
