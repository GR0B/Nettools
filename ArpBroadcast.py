#!/usr/bin/python
# Robert Sturzbecher 2022-10-15
# Sends an ARP broadcast packets.
# Requires scapy, by default is already installed on Kali else install with "pip install scapy", requires root/sudo  

#import sys
import argparse
from scapy.all import *

def ARP_Broadcast(mac, ip):
    srp(Ether(dst="ff:ff:ff:ff:ff:ff", src= mac)/ARP(op =2, pdst = "255.255.255.255", psrc = ip, hwdst="FF:FF:FF:FF:FF:FF",hwsrc=mac),timeout=0,verbose=False)
    print(f"Sent ARP Broadcast MAC:{mac} IP: {ip}")

def ARP_Anouncement(mac, ip):
    srp(Ether(dst="ff:ff:ff:ff:ff:ff", src= mac)/ARP(op =1, pdst = ip, psrc = ip, hwdst="00:00:00:00:00:00", hwsrc=mac),timeout=0,verbose=False)
    print(f"Sent ARP Anouncement MAC:{mac} IP: {ip}")

def GARP(mac, ip):
    srp(Ether(dst="ff:ff:ff:ff:ff:ff", src= mac)/ARP(op =2, pdst = ip, psrc = ip, hwdst=mac, hwsrc=mac),timeout=0,verbose=False)
    print(f"Sent GARP Broadcast MAC:{mac} IP: {ip}")

def rand_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        #0 keeps the IG and LG bits as false, could also do the same by only picking even numbers <126 but this also makes it easy to pick out our noise   
        0,
        random.randint(0, 255), 
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
        )

def rand_ip():   # keep in the 10.0.0.0/8 range and pick less common IPs. We are not a monster ;) 
    return "10.%s.%s.%s" % (
        random.randint(0, 255),
        random.randint(15, 255),
        random.randint(1, 254)
        )

if __name__ == '__main__':
    print("ArpSpoof          Robert Sturzbecher 2022-10-15")
    print("\nSends random ARP broadcasts")   
    parser = argparse.ArgumentParser(description='Send random ARP broadcasts')
    parser.add_argument('-t', "--type", type=int, help='ARP Broadcast type, \n\t 1=GARP\n\t 2=Anouncement\n\t 3=Broadcast', default=1)
    parser.add_argument('-n', "--number",type=int, help='Broadcast send number, default=1 ', default=1)
    args = parser.parse_args()

    for i in range(args.number):    
        match args.type:
            case 1:
                GARP(rand_mac(), rand_ip())
            case 2:
                ARP_Anouncement(rand_mac(), rand_ip())
            case 3:
                ARP_Broadcast(rand_mac(), rand_ip())
            case _:
                print("Type needs to be one of the following:\n\t 1=GARP\n\t 2=Anouncement\n\t 3=Broadcast")
                