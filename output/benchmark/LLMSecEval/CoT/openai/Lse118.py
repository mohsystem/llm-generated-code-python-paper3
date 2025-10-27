import os
from secrets import SystemRandom

def generate_and_write(file_path: str) -> str:
    if file_path is None:
        raise ValueError("file_path cannot be None")

    rng = SystemRandom()
    f1 = rng.random()
    f2 = rng.random()
    f3 = rng.random()

    concatenated = f"{f1},{f2},{f3}"

    # Normalize and ensure the directory exists if needed (only if a directory is provided)
    path = os.path.abspath(file_path)
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(concatenated)

    return concatenated

if __name__ == "__main__":
    files = [
        "py_out_1.txt",
        "py_out_2.txt",
        "py_out_3.txt",
        "py_out_4.txt",
        "py_out_5.txt",
    ]
    for f in files:
        result = generate_and_write(f)
        print(f"Wrote to {f}: {result}")