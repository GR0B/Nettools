# Robert Sturzbecher 2025-04-09
# Does a tracert to a TCP port under Windows
import socket  # Needed for resolving hostnames
from scapy.all import IP, TCP, sr1  # Scapy for crafting packets
import time
import argparse

def resolve_ip_to_hostname(ip_address):     # this is slow, takes a few seconds each time so may not be worth it
    try:
        hostname, alias, ip = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return f"could not be resolved"

def tcp_traceroute(destination, port, max_hops=30, timeout=2):
    print(f"Tracing route to {destination} on port {port} with TCP:")
    
    try:
        dest_ip = socket.gethostbyname(destination)  # Resolve hostname to IP
        print(f"Destination resolved to {dest_ip}\n")
    except socket.gaierror as e:
        print(f"Error resolving destination: {e}")
        return

    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=destination, ttl=ttl) / TCP(dport=port, flags="S")
        start_time = time.time()

        # Send the packet and wait for a response
        reply = sr1(pkt, timeout=timeout, verbose=0)
        elapsed_time = (time.time() - start_time) * 1000  # Convert to milliseconds

        if reply is None:
            print(f"\t{ttl}\tRequest timed out")
        elif reply.haslayer("ICMP") and reply.getlayer("ICMP").type == 11:  # Time Exceeded
            print(f"ICMP:\t{ttl}\t{reply.src}\t{elapsed_time:.2f} ms\t{resolve_ip_to_hostname(reply.src)}")
        elif reply.haslayer("TCP") and reply.getlayer("TCP").flags == 0x12:  # SYN-ACK
            print(f"TCP:\t{ttl}\t{reply.src}\t{elapsed_time:.2f} ms\t{resolve_ip_to_hostname(reply.src)}")
            print("Trace complete.")
            break
        elif reply.haslayer("ICMP") and reply.getlayer("ICMP").type in [3, 1]:  # Destination Unreachable
            print(f"\t{ttl}\tDestination unreachable")
            break
        else:
            print(f"{ttl}\tUnexpected reply received")

if __name__ == "__main__":
    print("\nTCP Traceroute \n\tRobert Sturzbecher 2025-04-09\n")
    parser = argparse.ArgumentParser(description="Performs a traceroute to a TCP port")
    parser.add_argument("destination", help="The destination hostname or IP address (e.g., www.google.com).")
    parser.add_argument("port", nargs="?", type=int, default=80, help="The TCP port to trace (default: 80).")
    args = parser.parse_args()
    destination = args.destination
    port = args.port
    tcp_traceroute(destination, port)
