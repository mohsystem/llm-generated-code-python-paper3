class RNG:
    def __init__(self, seed: int):
        # SplitMix64 to scramble the seed into a 32-bit non-zero state
        z = (seed + 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9 & ((1 << 64) - 1)
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB & ((1 << 64) - 1)
        z = (z ^ (z >> 31)) & ((1 << 64) - 1)
        self.state = z & 0xFFFFFFFF
        if self.state == 0:
            self.state = 0x6D2B79F5  # Non-zero default

    def _next_uint32(self) -> int:
        x = self.state & 0xFFFFFFFF
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
        self.state = x & 0xFFFFFFFF
        return self.state

    def rand7(self) -> int:
        LIMIT = 4294967291  # floor((2^32)/7)*7 - 1
        while True:
            u = self._next_uint32()
            if u <= LIMIT:
                return 1 + (u % 7)

    def rand10(self) -> int:
        while True:
            a = self.rand7()
            b = self.rand7()
            idx = (a - 1) * 7 + b  # 1..49
            if idx <= 40:
                return 1 + (idx - 1) % 10


def run_test(n: int, seed: int):
    if n < 0:
        raise ValueError("n must be non-negative")
    rng = RNG(seed)
    return [rng.rand10() for _ in range(n)]


if __name__ == "__main__":
    tests = [1, 2, 3, 5, 10]
    seeds = [12345, 67890, 13579, 24680, 424242]
    for n, s in zip(tests, seeds):
        out = run_test(n, s)
        print("[" + ",".join(str(x) for x in out) + "]")