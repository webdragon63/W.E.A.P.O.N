import argparse
import ipaddress
import socket
import subprocess
from scapy.all import ARP, Ether, srp, conf

def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except:
        return '127.0.0.1'
    finally:
        s.close()

def arp_scan(target_subnet):
    print(f"[*] Performing ARP scan on {target_subnet}...\n")
    conf.verb = 0
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_subnet)
    ans, _ = srp(packet, timeout=2, retry=1)

    for _, rcv in ans:
        print(f"[+] {rcv.psrc} \t {rcv.hwsrc}")

def port_scan(ip, ports):
    print(f"[*] Scanning {ip} on specified ports:")
    open_ports = []
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(0.05)
            s.connect((ip, port))
            print(f"[+] Port {port} is OPEN")
            open_ports.append(port)
            s.close()
        except:
            continue
    return open_ports

def smb_enum(ip):
    print(f"[*] Attempting SMB enumeration on {ip}...\n")
    try:
        output = subprocess.check_output(["nmblookup", "-A", ip], stderr=subprocess.DEVNULL).decode()
        print(output)
    except subprocess.CalledProcessError:
        print(f"[!] Failed SMB enum on {ip}")

def parse_ports(port_string):
    ports = set()
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def main():
    parser = argparse.ArgumentParser(description="Navigation Recon Module for W.E.A.P.O.N.")
    parser.add_argument("--arp", metavar="subnet", help="Perform ARP scan (e.g. 192.168.1.0/24)")
    parser.add_argument("--pscan", nargs=2, metavar=("target", "ports"), help="Port scan: IP and ports (e.g. 192.168.1.1 22,80,443 or 1-1024)")
    parser.add_argument("--smb", metavar="ip", help="Perform SMB NetBIOS enumeration")
    parser.add_argument("--auto", action="store_true", help="Auto ARP scan local subnet")

    args = parser.parse_args()

    if args.arp:
        arp_scan(args.arp)
    elif args.pscan:
        ip, port_range = args.pscan
        ports = parse_ports(port_range)
        port_scan(ip, ports)
    elif args.smb:
        smb_enum(args.smb)
    elif args.auto:
        ip = local_ip()
        subnet = ip.rsplit('.', 1)[0] + '.0/24'
        arp_scan(subnet)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

