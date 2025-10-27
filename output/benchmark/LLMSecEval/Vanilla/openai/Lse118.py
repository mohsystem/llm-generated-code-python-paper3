import random

def generate_and_write(file_path: str, seed: int | None = None) -> str:
    rng = random.Random(seed)
    f1, f2, f3 = rng.random(), rng.random(), rng.random()
    concatenated = f"{f1},{f2},{f3}"
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(concatenated)
    return concatenated

if __name__ == "__main__":
    print(generate_and_write("out_py_1.txt", 1))
    print(generate_and_write("out_py_2.txt", 2))
    print(generate_and_write("out_py_3.txt", 3))
    print(generate_and_write("out_py_4.txt", 4))
    print(generate_and_write("out_py_5.txt", 5))