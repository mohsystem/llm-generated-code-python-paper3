# Chain-of-Through Step 1: Implement rand10 using only rand7.
# Steps 2-5: Use internal PRNG (no built-ins), rejection sampling for uniformity.

# Xorshift64 PRNG (no built-in randomness)
_rng_state = 0x123456789ABCDEF

def _next64():
    global _rng_state
    x = _rng_state & ((1 << 64) - 1)
    x ^= (x << 13) & ((1 << 64) - 1)
    x ^= (x >> 7)
    x ^= (x << 17) & ((1 << 64) - 1)
    _rng_state = x & ((1 << 64) - 1)
    return _rng_state & ((1 << 63) - 1)  # 63-bit non-negative

def rand7():
    limit = 2147483646  # 7 * floor(2^31 / 7)
    while True:
        v = _next64() & ((1 << 31) - 1)  # 31-bit non-negative
        if v <= limit:
            return int(v % 7) + 1

def rand10():
    while True:
        a = rand7()
        b = rand7()
        idx = (a - 1) * 7 + b  # 1..49
        if idx <= 40:
            return 1 + (idx - 1) % 10

def run_test(n):
    if n < 0:
        raise ValueError("n must be non-negative")
    return [rand10() for _ in range(n)]

def _print_array(arr):
    print('[' + ','.join(str(x) for x in arr) + ']')

if __name__ == '__main__':
    tests = [1, 2, 3, 5, 20]  # 5 test cases
    for n in tests:
        _print_array(run_test(n))