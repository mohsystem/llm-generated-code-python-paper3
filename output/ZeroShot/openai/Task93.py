from typing import List, Tuple

def read_and_sort_key_values(file_path: str) -> List[str]:
    items: List[Tuple[str, str]] = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#") or line.startswith(";"):
                continue
            if "=" not in line:
                continue
            idx = line.find("=")
            if idx <= 0:
                continue
            key = line[:idx].strip()
            value = line[idx + 1 :].strip()
            if not key:
                continue
            items.append((key, value))
    items.sort(key=lambda kv: (kv[0], kv[1]))
    return [f"{k}={v}" for k, v in items]

def _write_file(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8", errors="strict") as f:
        f.write(content)

def main():
    f1 = "task93_test1.txt"
    f2 = "task93_test2.txt"
    f3 = "task93_test3.txt"
    f4 = "task93_test4.txt"
    f5 = "task93_test5.txt"

    _write_file(f1, "b=2\na=1\nc=3\n")
    _write_file(f2, "  x = 10 \n\n=bad\n y= 5  \n  # comment\n")
    _write_file(f3, "a=2\na=1\n")
    _write_file(f4, "# comment\nfoo=bar\ninvalid line\nk=v=extra\n; another comment\n")
    _write_file(f5, "Apple=1\napple=2\nß=sharp\nss=double\n A=9 \n")

    for i, fp in enumerate([f1, f2, f3, f4, f5], start=1):
        print(f"Test {i}:")
        for line in read_and_sort_key_values(fp):
            print(line)

if __name__ == "__main__":
    main()