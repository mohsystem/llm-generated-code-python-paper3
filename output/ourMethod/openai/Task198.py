from typing import List

# Park-Miller LCG parameters
MOD: int = 2147483647  # 2^31 - 1
MUL: int = 48271
seed: int = 123456789

def rng_next() -> int:
    global seed
    seed = (seed * MUL) % MOD  # 1..MOD-1
    return seed

def rng_uniform(k: int) -> int:
    if not isinstance(k, int) or k <= 0:
        raise ValueError("k must be positive int")
    m1 = MOD - 1  # 2147483646
    limit = (m1 // k) * k
    while True:
        r = rng_next() - 1  # 0..m1-1
        if r < limit:
            return r % k

# Given API
def rand7() -> int:
    return rng_uniform(7) + 1  # 1..7

# Required function
def rand10() -> int:
    while True:
        a = rand7()
        b = rand7()
        num = (a - 1) * 7 + b  # 1..49
        if num <= 40:
            return 1 + (num - 1) % 10

def run_rand10_n_times(n: int) -> List[int]:
    if not isinstance(n, int) or n < 1 or n > 100000:
        raise ValueError("n out of range")
    return [rand10() for _ in range(n)]

def print_array(arr: List[int]) -> None:
    print("[" + ",".join(str(x) for x in arr) + "]")

if __name__ == "__main__":
    tests = [1, 2, 3, 5, 10]
    for n in tests:
        print_array(run_rand10_n_times(n))