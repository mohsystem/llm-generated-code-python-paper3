import os
import tempfile
import random

def create_unicode_temp_file(length: int) -> str:
    pool = [
        ord('A'), ord('B'), ord('C'), ord('x'), ord('y'), ord('z'),
        ord('0'), ord('1'), ord('2'), ord('3'),
        0x00E9,  # é
        0x03B1,  # α
        0x0416,  # Ж
        0x4E2D,  # 中
        0x6F22,  # 漢
        0x3042,  # あ
        0x20AC,  # €
        0x1F642, # 🙂
        0x1F9E1, # 🧡
    ]
    cps = [random.choice(pool) for _ in range(length)]
    random_str = ''.join(chr(cp) for cp in cps)
    parts = []
    for cp in cps:
        hex_str = f"{cp:X}"
        width = 4 if cp <= 0xFFFF else 6
        parts.append("U+" + hex_str.zfill(width))
    unicode_notation = ' '.join(parts)
    content = random_str + "\n" + unicode_notation

    with tempfile.NamedTemporaryFile(delete=False, prefix="task88_", suffix=".txt", mode="w", encoding="utf-8") as f:
        f.write(content)
        path = f.name
    return os.path.abspath(path)

if __name__ == "__main__":
    print(create_unicode_temp_file(8))
    print(create_unicode_temp_file(10))
    print(create_unicode_temp_file(12))
    print(create_unicode_temp_file(14))
    print(create_unicode_temp_file(16))