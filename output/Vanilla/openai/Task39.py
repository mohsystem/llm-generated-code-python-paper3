import subprocess
import os

def display_file(filename: str) -> str:
    if os.name == "nt":
        cmd = ["cmd", "/c", "type", filename]
    else:
        cmd = ["cat", filename]
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.stdout

if __name__ == "__main__":
    test_files = [
        "py_file1.txt",
        "py_empty.txt",
        "py multi line.txt",
        "py_unicode.txt",
        "py_numbers.txt",
    ]
    contents = [
        "Hello from Python\nSecond line\n",
        "",
        "Alpha\nBeta\nGamma\n",
        "こんにちは世界\nПривет мир\nHola mundo\n",
        "10\n20\n30\n40\n50\n",
    ]
    for name, data in zip(test_files, contents):
        with open(name, "w", encoding="utf-8") as f:
            f.write(data)
    for name in test_files:
        print(f"--- {name} ---")
        print(display_file(name), end="")