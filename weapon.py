import argparse
import importlib
import sys
import os
import json
from colorama import Fore, Style, init
print(f"\n{Fore.CYAN}")
# Framework Banner
BANNER = r"""
          _  _  _   _______   _______    _____     _____    __   _
          |  |  |   |______   |_____|   |_____]   |     |   | \  |
          |__|__| . |______ . |     | . |       . |_____| . |  \_|
          
________________________________________________________________________________
W.E.A.P.O.N. - Wireless Exploitation Access Persistence Obfuscation & Navigation
                                 by WebDragon63
________________________________________________________________________________
"""

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


def list_modules():
    print(f"\n{Fore.CYAN}[*] Available modules:{Fore.WHITE}\n")
    for name in sorted(MODULES.keys()):
        print(f" {Fore.WHITE}- {Fore.MAGENTA}{name}")
    print()


def list_targets():
    try:
        with open(TARGETS_PATH, "r") as f:
            targets = json.load(f)
        print(f"\n{Fore.MAGENTA}[*] Known Targets:{Fore.YELLOW}")
        for target in targets:
            print(f" {Fore.WHITE}- {Fore.YELLOW}{target['ip']} ({target['os']})")
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to load targets.json: {Fore.WHITE}{e}")


def list_config():
    try:
        with open(CONFIG_PATH, "r") as f:
            modules = json.load(f)
        print(f"\n{Fore.MAGENTA}[*] Module Status:{Fore.WHITE}")
        for mod, status in modules.items():
            print(f" {Fore.WHITE}- {Fore.MAGENTA}{mod}: {Fore.YELLOW}{'enabled' if status else 'disabled'}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading configuration: {Fore.WHITE}{module_name}{e}")


def launch_module(module_name, args):
    if module_name not in MODULES:
        print(f"{Fore.RED}[!] Unknown module: {Fore.WHITE}{module_name}")
        list_modules()
        return

    try:
        mod = importlib.import_module(MODULES[module_name])
        if hasattr(mod, "main"):
            sys.argv = [module_name] + args
            mod.main()
        else:
            print(f"{Fore.RED}[!] Module '{module_name}' does not implement a main() function.{Fore.WHITE}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error launching module '{module_name}': {module_name}{e}")


def main():
    parser = argparse.ArgumentParser(description="W.E.A.P.O.N. Red Team Framework")
    parser.add_argument("module", nargs="?", help="Module to execute")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Arguments to pass to the module")
    args = parser.parse_args()

    print(BANNER)
    print (f"{Fore.WHITE}")
    if not args.module:
        list_modules()
        return

    if args.module == "targets":
        list_targets()
    elif args.module == "modules":
        list_config()
    else:
        launch_module(args.module, args.args)


if __name__ == "__main__":
    main()
