# Chain-of-Through:
# 1) Understand: Safely copy user input into a fixed-size buffer.
# 2) Security: No overflow; handle None and negative sizes.
# 3) Implementation: Clamp size, slice string.
# 4) Review: No risky operations; no external input used in tests.
# 5) Output: Final safe function.

def handle_input_to_fixed_buffer(input_str: str, buffer_size: int) -> str:
    if buffer_size is None or buffer_size < 0:
        buffer_size = 0
    if input_str is None:
        input_str = ""
    return input_str[:buffer_size]


if __name__ == "__main__":
    tests = [
        ("Hello", 10),
        ("HelloWorld", 5),
        ("", 8),
        ("SafeBuffer123", 12),
        ("EdgeCase", 0),
    ]
    for idx, (s, n) in enumerate(tests, 1):
        out = handle_input_to_fixed_buffer(s, n)
        print(f"Test {idx}: input=\"{s}\", size={n} -> \"{out}\"")