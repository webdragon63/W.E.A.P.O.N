import argparse
import importlib
import sys
import os
import json
import time
from colorama import Fore, Style, init
import readline  # For better CLI experience
init(autoreset=True)

# Framework Banner
BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
          _  _  _   _______   _______    _____     _____    __   _
          |  |  |   |______   |_____|   |_____]   |     |   | \  |
          |__|__| . |______ . |     | . |       . |_____| . |  \_|
          
________________________________________________________________________________
W.E.A.P.O.N. - Wireless Exploitation Access Persistence Obfuscation & Navigation
                                 by WebDragon63
________________________________________________________________________________
{Style.RESET_ALL}"

# Module name to Python path map
MODULES = {
    "access":         "modules.access.access_tool",
    "wireless":       "modules.wireless.wireless_tool",
    "navigation":     "modules.navigation.nav_recon",
    "exploit":        "modules.exploitation.exploit_launcher",
    "obfuscate":      "modules.obfuscation.obfuscator",
    "persist":        "modules.persistence.persist",
    "beacon":         "core.beacon.beacon_creator",
    "aes":            "core.crypto.aes_crypto",
    "chacha":         "core.crypto.chacha20_poly1305",
    "xor":            "core.crypto.xor_encoder",
    "keygen":         "core.crypto.keygen",
    "loader_exe":     "core.loader.exe_stub_loader",
    "loader_hta":     "core.loader.hta_loader",
    "loader_macro":   "core.loader.macro_generator",
    "loader_ps":      "core.loader.powershell_loader"
}

CONFIG_PATH = "configs/modules.json"
TARGETS_PATH = "configs/targets.json"


def animate_banner():
    for line in BANNER.splitlines():
        print(line)
        time.sleep(0.02)


def list_modules():
    print(f"\n{Fore.CYAN}[*] Available modules:{Style.RESET_ALL}\n")
    for name in sorted(MODULES.keys()):
        print(f" - {Fore.CYAN}{name}{Style.RESET_ALL}")
    print()


def list_targets():
    try:
        with open(TARGETS_PATH, "r") as f:
            targets = json.load(f)
        print(f"\n{Fore.CYAN}[*] Known Targets:{Style.RESET_ALL}")
        for target in targets:
            print(f" - {Fore.CYAN}{target['ip']} ({target['os']}){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to load targets.json: {e}{Style.RESET_ALL}")


def list_config():
    try:
        with open(CONFIG_PATH, "r") as f:
            modules = json.load(f)
        print(f"\n{Fore.CYAN}[*] Module Status:{Style.RESET_ALL}")
        for mod, status in modules.items():
            state = f"{'ENABLED' if status else 'DISABLED'}"
            color = Fore.GREEN if status else Fore.RED
            print(f" - {mod}: {color}{state}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading configuration: {e}{Style.RESET_ALL}")


def launch_module(module_name, args):
    if module_name not in MODULES:
        print(f"{Fore.RED}[!] Unknown module: {module_name}{Style.RESET_ALL}")
        list_modules()
        return

    try:
        mod = importlib.import_module(MODULES[module_name])
        if hasattr(mod, "main"):
            sys.argv = [module_name] + args
            mod.main()
        else:
            print(f"{Fore.RED}[!] Module '{module_name}' does not implement a main() function.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error launching module '{module_name}': {e}{Style.RESET_ALL}")


def gui_interface():
    while True:
        try:
            user_input = input(f"{Fore.CYAN}W.E.A.P.O.N> {Style.RESET_ALL}").strip()
            if not user_input:
                continue
            if user_input in ("exit", "quit"):
                print("\nExiting W.E.A.P.O.N...\n")
                break
            tokens = user_input.split()
            module = tokens[0]
            args = tokens[1:]

            if module == "help":
                list_modules()
            elif module == "targets":
                list_targets()
            elif module == "modules":
                list_config()
            else:
                launch_module(module, args)
        except KeyboardInterrupt:
            print("\n[!] Ctrl+C detected. Exiting shell mode.")
            break
        except Exception as e:
            print(f"{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="W.E.A.P.O.N. Red Team Framework")
    parser.add_argument("module", nargs="?", help="Module to execute")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Arguments to pass to the module")
    args = parser.parse_args()

    animate_banner()

    if not args.module:
        gui_interface()
    elif args.module == "targets":
        list_targets()
    elif args.module == "modules":
        list_config()
    else:
        launch_module(args.module, args.args)


if __name__ == "__main__":
    main()

