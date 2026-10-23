#!/usr/bin/env python3
"""CodeAlpha Task 1: Basic Network Sniffer.
Captures packets and prints source/destination IPs, protocol, ports and a payload preview.
Run with root privileges: sudo python3 sniffer.py -c 20
Only capture traffic on networks you own or have permission to monitor."""
import argparse
from collections import Counter
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, Raw

stats = Counter()

def preview(data, n=48):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in bytes(data)[:n])

def handle(pkt):
    ip = pkt[IP] if IP in pkt else pkt[IPv6] if IPv6 in pkt else None
    if ip is None:
        stats["other"] += 1
        return
    proto, info = "OTHER", ""
    if TCP in pkt:
        proto, info = "TCP", f"{pkt[TCP].sport} -> {pkt[TCP].dport} flags={pkt[TCP].flags}"
    elif UDP in pkt:
        proto, info = "UDP", f"{pkt[UDP].sport} -> {pkt[UDP].dport}"
        if DNS in pkt and pkt[DNS].qd is not None:
            proto, info = "DNS", f"query {pkt[DNS].qd.qname.decode(errors='ignore')}"
    elif ICMP in pkt:
        proto, info = "ICMP", f"type={pkt[ICMP].type}"
    stats[proto] += 1
    line = f"[{proto:5}] {ip.src:>15} -> {ip.dst:<15} {info}"
    if Raw in pkt:
        line += f"\n        payload: {preview(pkt[Raw].load)}"
    print(line)

def main():
    p = argparse.ArgumentParser(description="Basic network sniffer")
    p.add_argument("-i", "--iface", help="interface (default: scapy's default)")
    p.add_argument("-c", "--count", type=int, default=0, help="packets to capture (0 = until Ctrl+C)")
    p.add_argument("-f", "--filter", default="", help='BPF filter, e.g. "tcp port 80"')
    a = p.parse_args()
    try:
        sniff(iface=a.iface, count=a.count, filter=a.filter or None, prn=handle, store=False)
    except KeyboardInterrupt:
        pass
    print("\nSummary:", dict(stats))

if __name__ == "__main__":
    main()
