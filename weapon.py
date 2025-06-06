import argparse
import importlib
import sys
import os
import json

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
    print("\n[*] Available modules:\n")
    for name in sorted(MODULES.keys()):
        print(f" - {name}")
    print()


def list_targets():
    try:
        with open(TARGETS_PATH, "r") as f:
            targets = json.load(f)
        print("\n[*] Known Targets:")
        for target in targets:
            print(f" - {target['ip']} ({target['os']})")
    except Exception as e:
        print(f"[!] Failed to load targets.json: {e}")


def list_config():
    try:
        with open(CONFIG_PATH, "r") as f:
            modules = json.load(f)
        print("\n[*] Module Status:")
        for mod, status in modules.items():
            print(f" - {mod}: {'enabled' if status else 'disabled'}")
    except Exception as e:
        print(f"[!] Error reading configuration: {e}")


def launch_module(module_name, args):
    if module_name not in MODULES:
        print(f"[!] Unknown module: {module_name}")
        list_modules()
        return

    try:
        mod = importlib.import_module(MODULES[module_name])
        if hasattr(mod, "main"):
            sys.argv = [module_name] + args
            mod.main()
        else:
            print(f"[!] Module '{module_name}' does not implement a main() function.")
    except Exception as e:
        print(f"[!] Error launching module '{module_name}': {e}")


def main():
    parser = argparse.ArgumentParser(description="W.E.A.P.O.N. Red Team Framework")
    parser.add_argument("module", nargs="?", help="Module to execute")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Arguments to pass to the module")
    args = parser.parse_args()

    print(BANNER)

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

