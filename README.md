# CodeAlpha_NetworkSniffer

CodeAlpha Cyber Security Internship, Task 1: a basic network sniffer in Python using `scapy`.

It captures packets and shows each packet's time, protocol (TCP, UDP, DNS, ICMP, ARP), source and destination IP and port, TCP flags, DNS queries, and a readable preview of the payload. At the end it prints a per-protocol summary.

## Setup
```bash
pip install -r requirements.txt
```
Windows users also need [Npcap](https://npcap.com/).

## Usage
```bash
sudo python3 sniffer.py                      # live capture until Ctrl+C
sudo python3 sniffer.py -c 50 -f "tcp port 80"  # 50 HTTP packets
sudo python3 sniffer.py -c 100 -w out.pcap   # save a capture
python3 make_sample.py && python3 sniffer.py -r sample.pcap   # demo without root
```

## How it works
Packets travel in layers: Ethernet frames carry IP packets, which carry TCP or UDP segments, which carry application data such as HTTP or DNS. `scapy` decodes each layer, and the sniffer reads the fields from each one in turn.

Only capture traffic on networks you own or have permission to monitor.
