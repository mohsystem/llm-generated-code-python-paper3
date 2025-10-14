import tempfile
import os

def sort_key_value_file(file_path):
    pairs = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            t = line.strip()
            if not t or t.startswith('#'):
                continue
            pos_eq = t.find('=')
            pos_col = t.find(':')
            if pos_eq == -1 and pos_col == -1:
                continue
            if pos_eq == -1:
                idx = pos_col
            elif pos_col == -1:
                idx = pos_eq
            else:
                idx = min(pos_eq, pos_col)
            if idx <= 0:
                continue
            key = t[:idx].strip()
            value = t[idx+1:].strip()
            if not key:
                continue
            pairs.append((key, value))
    pairs.sort(key=lambda kv: (kv[0], kv[1]))
    return [f"{k}={v}" for k, v in pairs]

def _write_temp(content):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", prefix="task93_py_", mode='w', encoding='utf-8')
    try:
        tmp.write(content)
    finally:
        tmp.close()
    return tmp.name

if __name__ == "__main__":
    f1 = _write_temp("b=2\na=1\nc=3\n")
    f2 = _write_temp("orange:10\napple:20\nbanana:15\n")
    f3 = _write_temp(" # comment\n z : last \n\n a : first \n middle=between \n")
    f4 = _write_temp("dup=2\ndup=1\nsame:0\nsame:5\n")
    f5 = _write_temp("invalidline\n k=v\n x : y \n #comment \n :missingkey? \n =missingkey2 \n")

    print("Test1:", sort_key_value_file(f1))
    print("Test2:", sort_key_value_file(f2))
    print("Test3:", sort_key_value_file(f3))
    print("Test4:", sort_key_value_file(f4))
    print("Test5:", sort_key_value_file(f5))

    for p in [f1, f2, f3, f4, f5]:
        try:
            os.remove(p)
        except Exception:
            pass