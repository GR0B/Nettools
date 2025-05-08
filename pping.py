import sys
from scapy.all import IP, TCP, sr1

class colors:                                               # ANSI terminal color escape codes, excuse my american spelling here but that is how the ANSI standard spells it ;)
    RED = '\033[91m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    END = '\033[0m'

def syn_scan(ip, port):
    syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
    response = sr1(syn_packet, timeout=2, verbose=0)

    if response is None:
        print(f"{colors.YELLOW}{ip}:{port} FILTERED (No response){colors.END}")
    elif response.haslayer(TCP) and response[TCP].flags == 0x12:
        print(f"{colors.GREEN}{ip}:{port} OPEN (SYN-ACK received){colors.END}")
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:
        print(f"{colors.RED}{ip}:{port} CLOSED (RST received){colors.END}")
    else:
        print(f"{ip}:{port} Unexpected response, TCP Flags:{hex(response[TCP].flags)}")

if __name__ == "__main__":
    print("\tPortPing          Robert Sturzbecher 2025-05-08\n")
    if len(sys.argv) != 3:
        print("\tUsage: pping <IP> <Port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    syn_scan(target_ip, target_port)

