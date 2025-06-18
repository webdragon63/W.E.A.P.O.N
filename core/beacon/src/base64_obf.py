import base64
import sys

def obfuscate_base64(input_path, output_path):
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            original_code = f.read()
    except FileNotFoundError:
        return

    # Base64 encode
    encoded_code = base64.b64encode(original_code.encode()).decode()

    # Silent exec wrapper
    wrapper = f"""import base64;exec(base64.b64decode('{encoded_code}').decode())"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(wrapper)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    obfuscate_base64(input_file, output_file)

