import tempfile
import os

def read_file(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()

if __name__ == "__main__":
    contents = [
        "Python Test File 1\nLine A\nLine B",
        "Python Test File 2\nHello World",
        "Python Test File 3\nSample Content",
        "Python Test File 4\nLorem Ipsum",
        "Python Test File 5\nEnd of File"
    ]

    paths = []
    for i, text in enumerate(contents):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, prefix=f"task36_py_test_{i}_", suffix=".txt", encoding="utf-8") as tf:
            tf.write(text)
            paths.append(tf.name)

    for i, p in enumerate(paths):
        print(f"== Python Test {i + 1} ==")
        try:
            print(read_file(p))
        except Exception as e:
            print(f"Error reading file: {p} -> {e}")
        finally:
            try:
                os.remove(p)
            except Exception:
                pass