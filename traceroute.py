#!/usr/bin/python3
from scapy.all import *
from scapy.layers.inet import ICMP, IP

ttl = 0  # Set TTL = 0
traceroute = input("enter the IP: ")
while ttl <= 20:
    ttl += 1
    ip = IP(dst=traceroute, ttl=ttl)
    icmp = ICMP(type=8)  # Echo Request (Ping)
    newpkt = ip / icmp

    # Send the packet and capture the reply
    reply = sr1(newpkt, timeout=2, verbose=0)

    # Check if a reply was received
    if reply is None:
        print(f"Hop {ttl}: ****** - Expired (No reply)")
    elif reply.src == traceroute:  # If the reply comes from the destination IP, terminate the loop
        print(f"Hop {ttl}: Reached destination {reply.src}. Done.")
        break
    else:
        print(f"Hop {ttl}: Reply from {reply.src}")
