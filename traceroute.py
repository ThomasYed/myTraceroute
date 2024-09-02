#!/usr/bin/env python3

import sys
import socket
import time
import logging
from scapy.all import *
from scapy.layers.inet import *
import argparse

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def traceroute(destination, max_hops=30, timeout=3):
    destination_ip = socket.gethostbyname(destination)
    print(f"Traceroute to {destination} ({destination_ip}), {max_hops} hops max, {timeout} timeout")

    ttl = 1

    while ttl <= max_hops:
        # Create IP header
        ip_packet = IP(dst=destination_ip, ttl=ttl)

        # Add ICMP header
        pack = ip_packet / ICMP()

        # Send packet and check the time
        start_time = time.time()
        reply = sr1(pack, verbose=False, timeout=timeout)
        end_time = time.time()
        rtt = (end_time - start_time) * 1000

        if reply is None:
            # No answer
            print(f"{ttl}\t*")
        elif reply.src == destination_ip:
            # Destination reached
            print(f"{ttl}\t{reply.src}\t{rtt:.2f} ms")
            print("Trace complete!")
            break
        else:
            # Information about hop
            print(f"{ttl}\t{reply.src}\t{rtt:.2f} ms")

        ttl += 1


def main():
    pars = argparse.ArgumentParser(description="My traceroute")
    pars.add_argument("destination", help="Destination host or IP address.")
    pars.add_argument("-m", "--max-hops", type=int, default=30, help="Maximum number of hops (default: 30).")
    pars.add_argument("-t", "--timeout", type=int, default=2, help="Timeout for each packet in seconds (default: 3).")

    arguments = pars.parse_args()
    traceroute(arguments.destination, max_hops=arguments.max_hops, timeout=arguments.timeout)


if __name__ == "__main__":
    main()
