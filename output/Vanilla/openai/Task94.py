from typing import List, Tuple

def read_and_sort_key_value_file(path: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            p = _parse_line(line.rstrip("\n"))
            if p is not None:
                pairs.append(p)
    pairs.sort(key=lambda kv: (kv[0], kv[1]))
    return pairs

def _parse_line(line: str):
    if "=" not in line:
        return None
    k, v = line.split("=", 1)
    k = k.strip()
    v = v.strip()
    if not k and not v:
        return None
    return (k, v)

def _write_file(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def _run_test(title: str, path: str) -> None:
    print(f"== {title} ==")
    res = read_and_sort_key_value_file(path)
    for k, v in res:
        print(f"{k}={v}")
    print()

if __name__ == "__main__":
    f1 = "test1_kv_py.txt"
    f2 = "test2_kv_py.txt"
    f3 = "test3_kv_py.txt"
    f4 = "test4_kv_py.txt"
    f5 = "test5_kv_py.txt"

    _write_file(f1, "b=2\na=1\nc=3\n")
    _write_file(f2, "k=3\nk=1\nk=2\n")
    _write_file(f3, "  x  =  10  \ninvalid line\ny=5\n=onlyvalue\nonlykey=\n")
    _write_file(f4, "10=ten\n2=two\n1=one\n")
    _write_file(f5, "a= \n a=0\n b= \n z=last\n   \nnoequalsline\n")

    _run_test("Test 1", f1)
    _run_test("Test 2", f2)
    _run_test("Test 3", f3)
    _run_test("Test 4", f4)
    _run_test("Test 5", f5)