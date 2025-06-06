import argparse
import os
import sys
import subprocess

# Define paths for each module (adjust based on your setup)
MODULE_PATHS = {
    "wireless": "./modules/wireless/wireless_tool.py",
    "exploitation": "./modules/exploitation/exploit_launcher.py",
    "access": "./modules/access/access_tool.py",
    "persistence": "./modules/persistence/persist.py",
    "obfuscation": "./modules/obfuscation/obfuscator.py",
    "navigation": "./modules/navigation/nav_recon.py"
}

def run_module(module_name, args):
    path = MODULE_PATHS.get(module_name)
    if not path:
        print(f"[!] Module '{module_name}' not found.")
        sys.exit(1)

    if not os.path.exists(path):
        print(f"[!] Module file '{path}' does not exist.")
        sys.exit(1)

    try:
        # Run the module as a subprocess (supports Python or binary)
        if path.endswith('.py'):
            subprocess.run(["python3", path] + args)
        else:
            subprocess.run([path] + args)
    except Exception as e:
        print(f"[!] Error running module: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="W.E.A.P.O.N. - Red Team Modular Toolkit"
    )
    parser.add_argument(
        "module", choices=MODULE_PATHS.keys(),
        help="Module to run"
    )
    parser.add_argument(
        "args", nargs=argparse.REMAINDER,
        help="Arguments to pass to the module"
    )

    args = parser.parse_args()

    run_module(args.module, args.args)

if __name__ == "__main__":
    main()

