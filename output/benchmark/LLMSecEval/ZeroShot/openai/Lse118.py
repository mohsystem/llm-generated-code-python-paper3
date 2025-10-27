import os
from secrets import SystemRandom

def generate_and_write(file_path: str) -> str:
    rng = SystemRandom()
    a = rng.random()
    b = rng.random()
    c = rng.random()
    result = f"{a}{b}{c}"
    # Ensure the directory exists if a path is provided
    directory = os.path.dirname(os.path.abspath(file_path))
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    with open(file_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(result)
    return result

if __name__ == "__main__":
    files = ["py_out1.txt", "py_out2.txt", "py_out3.txt", "py_out4.txt", "py_out5.txt"]
    for fp in files:
        s = generate_and_write(fp)
        print(f"Wrote to {fp}: {s}")