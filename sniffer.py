#!/usr/bin/env python3
"""CodeAlpha Task 1: Basic Network Sniffer.

Captures packets with scapy and prints source/destination IPs, protocol,
ports, and a short payload preview. Run with root/admin privileges.

Usage:
  sudo python3 sniffer.py                  # capture until Ctrl+C
  sudo python3 sniffer.py -c 50 -f "tcp port 80" -i eth0
  python3 sniffer.py -r capture.pcap       # analyze a saved capture (no root)
  sudo python3 sniffer.py -c 100 -w out.pcap
"""
import argparse
from collections import Counter
from datetime import datetime

from scapy.all import sniff, rdpcap, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw

stats = Counter()
captured = []
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def preview(data: bytes, n: int = 48) -> str:
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:n])
    return text + ("..." if len(data) > n else "")


def describe(pkt) -> str:
    ts = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S")
    if ARP in pkt:
        stats["ARP"] += 1
        op = "who-has" if pkt[ARP].op == 1 else "is-at"
        return f"[{ts}] ARP     {pkt[ARP].psrc} -> {pkt[ARP].pdst} ({op})"
    ip = pkt[IP] if IP in pkt else pkt[IPv6] if IPv6 in pkt else None
    if ip is None:
        stats["Other"] += 1
        return f"[{ts}] OTHER   {pkt.summary()}"
    proto_num = ip.proto if IP in pkt else ip.nh
    proto = PROTO_NAMES.get(proto_num, str(proto_num))
    src, dst = ip.src, ip.dst
    info = ""
    if TCP in pkt:
        src, dst = f"{src}:{pkt[TCP].sport}", f"{dst}:{pkt[TCP].dport}"
        info = f"flags={pkt[TCP].flags}"
    elif UDP in pkt:
        src, dst = f"{src}:{pkt[UDP].sport}", f"{dst}:{pkt[UDP].dport}"
        if DNS in pkt and pkt[DNS].qd is not None:
            proto = "DNS"
            info = "query=" + pkt[DNS].qd.qname.decode(errors="ignore")
    elif ICMP in pkt:
        info = f"type={pkt[ICMP].type}"
    stats[proto] += 1
    line = f"[{ts}] {proto:<7} {src} -> {dst} len={len(pkt)} {info}".rstrip()
    if Raw in pkt:
        line += f"\n           payload: {preview(bytes(pkt[Raw].load))}"
    return line


def handle(pkt):
    captured.append(pkt)
    print(describe(pkt))


def main():
    ap = argparse.ArgumentParser(description="Basic network sniffer (CodeAlpha Task 1)")
    ap.add_argument("-i", "--iface", help="interface to sniff on (default: scapy's choice)")
    ap.add_argument("-c", "--count", type=int, default=0, help="packets to capture (0 = until Ctrl+C)")
    ap.add_argument("-f", "--filter", help='BPF filter, e.g. "tcp port 443"')
    ap.add_argument("-r", "--read", help="read packets from a .pcap file instead of live capture")
    ap.add_argument("-w", "--write", help="save captured packets to a .pcap file")
    a = ap.parse_args()

    if a.read:
        for p in rdpcap(a.read):
            handle(p)
    else:
        print("Sniffing... press Ctrl+C to stop.\n")
        sniff(iface=a.iface, filter=a.filter, prn=handle, count=a.count, store=False)

    print("\n=== Summary ===")
    print(f"Total packets: {len(captured)}")
    for proto, n in stats.most_common():
        print(f"  {proto:<7} {n}")
    if a.write:
        wrpcap(a.write, captured)
        print(f"Saved to {a.write}")


if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print("Permission denied: run with sudo (Linux/macOS) or as Administrator with Npcap (Windows).")
    except KeyboardInterrupt:
        pass
