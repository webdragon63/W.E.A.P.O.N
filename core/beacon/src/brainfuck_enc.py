import sys
import os

def ascii_to_brainfuck(text):
    bf_code = ""
    prev_ascii = 0

    for char in text:
        ascii_val = ord(char)
        diff = ascii_val - prev_ascii

        if diff > 0:
            bf_code += '+' * diff
        elif diff < 0:
            bf_code += '-' * (-diff)

        bf_code += '.'
        prev_ascii = ascii_val

    return bf_code

def main():
    if len(sys.argv) != 3:
        print("Usage: python brainfuck.py <input_file.py> <output_file.txt>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    if not os.path.isfile(input_file):
        print(f"[ERROR] Input file '{input_file}' not found.")
        sys.exit(1)

    with open(input_file, "r", encoding="utf-8") as f:
        input_text = f.read()

    bf_code = ascii_to_brainfuck(input_text)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(bf_code)

    print(f"[+] Encoded '{output_file}'")

if __name__ == "__main__":
    main()

