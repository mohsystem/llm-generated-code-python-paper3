# Chain-of-Through Secure Implementation
# 1) Problem understanding: safe string ops (copy, concat, manipulate).
# 2) Security: handle None, bounds, avoid large allocations.
# 3) Secure coding: validations and clamps.
# 4) Code review: no eval/exec, safe operations only.
# 5) Secure output: robust functions and tests.

def _s(val):
    return "" if val is None else str(val)

def copy_string(s):
    src = _s(s)
    return "" + src

def concat_strings(a, b):
    return _s(a) + _s(b)

def reverse_string(s):
    return _s(s)[::-1]

def replace_substring(s, target, replacement):
    src = _s(s)
    t = "" if target is None else str(target)
    r = "" if replacement is None else str(replacement)
    if t == "":
        return copy_string(src)
    return src.replace(t, r)

def safe_substring(s, start, length):
    src = _s(s)
    try:
        start = int(start)
        length = int(length)
    except Exception:
        return ""
    start = max(0, start)
    length = max(0, length)
    end = min(len(src), start + length)
    if start >= len(src) or length == 0:
        return ""
    return src[start:end]

def count_occurrences(s, sub):
    src = _s(s)
    needle = _s(sub)
    if needle == "":
        return 0
    count = 0
    i = 0
    L = len(needle)
    while True:
        idx = src.find(needle, i)
        if idx == -1:
            break
        count += 1
        i = idx + L
    return count

def repeat_string(s, times):
    src = _s(s)
    try:
        times = int(times)
    except Exception:
        return ""
    if times <= 0 or src == "":
        return ""
    # Simple guard to avoid huge allocations
    if len(src) * times > 10_000_000:
        raise ValueError("Result too large")
    return src * times

def to_upper(s):
    return _s(s).upper()

def to_lower(s):
    return _s(s).lower()

def trim_safe(s):
    return _s(s).strip()

if __name__ == "__main__":
    tests = [
        ("Hello", "World", "l", "L"),
        ("", "Test", "Test", "Exam"),
        ("  Spaces  ", "", " ", ""),
        ("abcabcabc", "xyz", "abc", "A"),
        (None, None, None, None),
    ]
    for i, (a, b, tgt, rep) in enumerate(tests, 1):
        print(f"=== Test {i} ===")
        print("copy_string(a):", copy_string(a))
        print("concat_strings(a,b):", concat_strings(a, b))
        print("reverse_string(a):", reverse_string(a))
        print("replace_substring(a,tgt,rep):", replace_substring(a, tgt, rep))
        print("safe_substring(a,1,3):", safe_substring(a, 1, 3))
        print("count_occurrences(a,tgt):", count_occurrences(a, tgt))
        print("repeat_string('ab',3):", repeat_string("ab", 3))
        print("to_upper(a):", to_upper(a))
        print("to_lower(a):", to_lower(a))
        print("trim_safe(a):", trim_safe(a))