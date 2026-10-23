"""Builds sample.pcap with a few example packets so the sniffer can be demoed without root."""
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, ARP, Raw, wrpcap
pkts = [
    Ether()/ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1"),
    Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=53000, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com")),
    Ether()/IP(src="192.168.1.10", dst="93.184.216.34")/TCP(sport=51000, dport=80, flags="S"),
    Ether()/IP(src="192.168.1.10", dst="93.184.216.34")/TCP(sport=51000, dport=80, flags="PA")/Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    Ether()/IP(src="192.168.1.10", dst="1.1.1.1")/ICMP(),
]
wrpcap("sample.pcap", pkts)
print("wrote sample.pcap")
