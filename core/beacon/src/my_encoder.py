# encode_txt.py
def encode_file(input_path, output_path, key=632627658752323):
    with open(input_path, "r") as f:
        data = f.read()
    encoded = [str(ord(c) + key) for c in data]
    with open(output_path, "w") as f:
        f.write(','.join(encoded))

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python encode_txt.py input.txt encoded_output.txt")
    else:
        encode_file(sys.argv[1], sys.argv[2])

