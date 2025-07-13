import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import importlib
import sys
import io
import subprocess
from configs.config import STAGER_KEY

MODULES = {
    "Access Tools": {
        "Access Tool":            "modules.access.access_tool"
    },
    "Wireless Tools": {
        "Wireless Scanner":       "modules.wireless.wireless_tool"
    },
    "Reconnaissance": {
        "Navigation Recon":       "modules.navigation.nav_recon"
    },
    "Exploitation": {
        "Exploit Launcher":       "modules.exploitation.exploit_launcher"
    },
    "Obfuscation": {
        "Dragon63 Encoder Lvl 1":     "core.beacon.lvl1",
        "Dragon63 Encoder Lvl 2":     "core.beacon.lvl2",
        "Stager Key Keygen":      "core.beacon.src.keygen",
    },
    "Beacons": {
        "Python Stageless Beacon for Linux":       "core.beacon.beacon_creator_lin",
        "Python Stageless Beacon for Windows":     "core.beacon.beacon_creator_win",
        "Powershell Stageless Beacon":             "core.beacon.powershell_beacon_creator",
    },
    "Crypto": {
        "AES_256_CBC":            "core.crypto.aes_crypto",
        "ChaCha20-Poly1305":      "core.crypto.chacha20_poly1305",
        "XOR Encoder":            "core.crypto.xor_encoder"
    },
    "Loaders": {
        "EXE Loader":             "core.loader.exe_stub_loader",
        "HTA Loader":             "core.loader.hta_loader",
        "Macro Generator":        "core.loader.macro_generator",
        "PowerShell Loader":      "core.loader.powershell_loader"
    }
}

BANNER_LINES = [
    "_  _  _   _______   _______    _____     _____    __   _",
    "|  |  |   |______   |_____|   |_____]   |     |   | \\  |",
    "        |__|__| . |______ . |     | . |       . |_____| . |  \\_| v:1.0.0",
    "________________________________________________________________________________",
    "W.E.A.P.O.N. - Wireless Exploitation Access Persistence Obfuscation & Navigation",
    "by WebDragon63",
    "________________________________________________________________________________"
]

class WeaponGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("W.E.A.P.O.N Framework GUI")
        self.geometry("1300x800")
        self.configure(bg="black")

        self.selected_category = tk.StringVar()
        self.selected_module = tk.StringVar()

        # Banner
        self.banner_label = tk.Label(self, text="", font=("Consolas", 14, "bold"), fg="#00ffff", bg="black")
        self.banner_label.pack(pady=10)
        self.banner_index = 0
        self.glow_state = True
        self.animate_banner()

        # Key Display
        key_frame = tk.Frame(self, bg="black")
        key_frame.pack(pady=5)
        tk.Label(key_frame, text="Stager Key For The Beacon:", fg="#FF00FF", bg="black", font=("Consolas", 10, "bold")).pack(side=tk.LEFT, padx=5)
        self.stager_key_entry = tk.Entry(key_frame, font=("Consolas", 10, "bold"), fg="cyan", bg="#1C1C1C", width=30, readonlybackground="black", relief=tk.FLAT)
        self.stager_key_entry.insert(0, STAGER_KEY)
        self.stager_key_entry.config(state='readonly')
        self.stager_key_entry.pack(side=tk.LEFT, padx=5)

        # Module selection frame
        frame = tk.Frame(self, bg="cyan")
        frame.pack(pady=10)

        tk.Label(frame, text="Category:", fg="#00ffff", bg="black", font=("Consolas", 12)).pack(side=tk.LEFT, padx=5)
        self.category_dropdown = ttk.Combobox(frame, textvariable=self.selected_category, values=list(MODULES.keys()), state="readonly", width=20)
        self.category_dropdown.pack(side=tk.LEFT, padx=5)
        self.category_dropdown.bind("<<ComboboxSelected>>", self.update_module_dropdown)

        tk.Label(frame, text="Module:", fg="#00ffff", bg="black", font=("Consolas", 12)).pack(side=tk.LEFT, padx=5)
        self.module_dropdown = ttk.Combobox(frame, textvariable=self.selected_module, state="readonly", width=30)
        self.module_dropdown.pack(side=tk.LEFT, padx=5)

        tk.Label(frame, text="Arguments:", fg="#00ffff", bg="black", font=("Consolas", 12)).pack(side=tk.LEFT, padx=5)
        self.args_entry = tk.Entry(
            frame,
            width=50,
            bg="#0F3F6F",              # Grey background
            fg="white",                # White text
            insertbackground="white",  # White cursor
            font=("Consolas", 10)
        )
        self.args_entry.pack(side=tk.LEFT, padx=5)

        self.run_button = tk.Button(self, text="Run Module", command=self.run_module_thread, bg="#00ffff", fg="black", font=("Consolas", 12, "bold"))
        self.run_button.pack(pady=10)

        self.launch_teamserver_button = tk.Button(self, text="Launch Teamserver", command=self.launch_teamserver, bg="#FF00FF", fg="black", font=("Consolas", 12, "bold"))
        self.launch_teamserver_button.pack(pady=10)

        self.output_text = scrolledtext.ScrolledText(self, bg="#2E2E2E", fg="#00ffff", insertbackground="#00ffff",font=("Consolas", 11), height=20, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.output_text.configure(state=tk.DISABLED)

    def animate_banner(self):
        color_on = "#00ffff"
        color_off = "#003333"
        text = "\n".join(BANNER_LINES)
        color = color_on if self.glow_state else color_off
        self.banner_label.config(text=text, fg=color)
        self.glow_state = not self.glow_state
        self.after(600, self.animate_banner)

    def update_module_dropdown(self, event=None):
        category = self.selected_category.get()
        if category in MODULES:
            self.module_dropdown['values'] = list(MODULES[category].keys())
            self.module_dropdown.current(0)
            self.selected_module.set(self.module_dropdown['values'][0])

    def run_module_thread(self):
        threading.Thread(target=self.run_module, daemon=True).start()

    def run_module(self):
        category = self.selected_category.get()
        module_name = self.selected_module.get()
        args_text = self.args_entry.get()
        args = args_text.split() if args_text else []

        if category not in MODULES or module_name not in MODULES[category]:
            self.append_output(f"[!] Unknown module: {module_name} in category: {category}\n")
            return

        try:
            mod = importlib.import_module(MODULES[category][module_name])
            if not hasattr(mod, "main"):
                self.append_output(f"[!] Module '{module_name}' does not implement a main() function.\n")
                return

            old_stdout, old_stderr = sys.stdout, sys.stderr
            sys.stdout = sys.stderr = io.StringIO()
            sys.argv = [module_name] + args

            try:
                mod.main()
            except SystemExit:
                pass

            output = sys.stdout.getvalue()
            self.append_output(output)

        except Exception as e:
            self.append_output(f"[!] Error launching module '{module_name}': {e}\n")

        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def launch_teamserver(self):
        threading.Thread(target=self._start_teamserver_process, daemon=True).start()

    def _start_teamserver_process(self):
        try:
            cmd = ["python3", "modules/teamserver/teamserver.py"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            self.append_output("[*] Launching teamserver...\n")
            for line in proc.stdout:
                self.append_output(line)
            for line in proc.stderr:
                self.append_output(line)
            proc.wait()
            self.append_output(f"\n[Teamserver exited with code {proc.returncode}]\n")
        except Exception as e:
            self.append_output(f"[!] Failed to launch teamserver: {e}\n")

    def append_output(self, text):
        self.output_text.configure(state=tk.NORMAL)
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.configure(state=tk.DISABLED)

def main():
    app = WeaponGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
