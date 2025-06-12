import base64
import argparse

def build_standalone_decoder(encoded_data, output_path):
    # Build the decoder script with embedded obfuscated data
    decoder_code = f"""import base64

def pref():
    b = "QH0dWKJDAQ=="
    m = 0x42424242424242

    o = base64.b64decode(b)
    t = int.from_bytes(o, byteorder="big")
    key = t ^ m

    m = "{encoded_data}".split(',')

    try:
        chars = [chr(int(n) - key) for n in m]
        code = ''.join(chars)
    except Exception as e:
        print(f"[ERROR] Decoding failed: {{e}}")
        return


    try:
        exec(code, globals())
    except Exception as e:
        print(f"[ERROR] Execution failed: {{e}}")

if __name__ == "__main__":
    pref()
"""
    with open(output_path, "w") as f:
        f.write(decoder_code)


def main():
    parser = argparse.ArgumentParser(
        description="Standalone Decoder Builder\n\n"
                    "This script reads an obfuscated code file (comma-separated integers) and generates a standalone "
                    "Python script that embeds both the decoder and the encoded payload.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("input", help="Path to encoded output file (e.g., encoded_output.txt)")
    parser.add_argument("output", help="Path to write the standalone Python file (e.g., standalone_decoder.py)")

    args = parser.parse_args()

    try:
        with open(args.input, "r") as f:
            encoded_data = f.read().strip()
    except Exception as e:
        print(f"[ERROR] Failed to read input file: {e}")
        return

    build_standalone_decoder(encoded_data, args.output)

if __name__ == "__main__":
    main()

