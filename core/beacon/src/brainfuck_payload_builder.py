# make_standalone_decoder.py

import argparse

def generate_standalone_decoder(enc_file, output_file):
    try:
        with open(enc_file, "r", encoding="utf-8") as f:
            bf_code = f.read().strip()
    except FileNotFoundError:
        print(f"[!] Error: File '{enc_file}' not found.")
        return

    # Escape triple quotes and backslashes
    escaped_code = bf_code.replace('\\', '\\\\').replace('"""', '\\"\\"\\"')

    standalone_code = f'''\

def ncode(code, input_stream=""):
    tape = [0] * 30000
    ptr = 0
    code_ptr = 0
    input_ptr = 0
    output = ""
    bracket_map = {{}}

    # Precompute bracket pairs
    stack = []
    for i, cmd in enumerate(code):
        if cmd == '[':
            stack.append(i)
        elif cmd == ']':
            if not stack:
                raise SyntaxError(f"Unmatched ']' at position {{i}}")
            start = stack.pop()
            bracket_map[start] = i
            bracket_map[i] = start
    if stack:
        raise SyntaxError("Unmatched '[' in code")

    while code_ptr < len(code):
        cmd = code[code_ptr]

        if cmd == '>':
            ptr += 1
        elif cmd == '<':
            ptr -= 1
        elif cmd == '+':
            tape[ptr] = (tape[ptr] + 1) % 256
        elif cmd == '-':
            tape[ptr] = (tape[ptr] - 1) % 256
        elif cmd == '.':
            output += chr(tape[ptr])
        elif cmd == ',':
            if input_ptr < len(input_stream):
                tape[ptr] = ord(input_stream[input_ptr])
                input_ptr += 1
            else:
                tape[ptr] = 0
        elif cmd == '[':
            if tape[ptr] == 0:
                code_ptr = bracket_map[code_ptr]
        elif cmd == ']':
            if tape[ptr] != 0:
                code_ptr = bracket_map[code_ptr]

        code_ptr += 1

    return output


if __name__ == "__main__":
    enc = """{escaped_code}"""
    python_code = ncode(enc)
    exec(python_code)
'''

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(standalone_code)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Embed enc.txt Brainfuck into standalone Python decoder.")
    parser.add_argument("input", help="Path to enc.txt file (Brainfuck-encoded Python)")
    parser.add_argument("output", help="Path to output Python file (standalone decoder)")
    args = parser.parse_args()

    generate_standalone_decoder(args.input, args.output)

