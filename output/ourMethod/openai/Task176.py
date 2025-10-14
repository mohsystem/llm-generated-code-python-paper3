from typing import List


class ProductOfNumbers:
    def __init__(self) -> None:
        # prefix products since last zero; pref[0] = 1
        self.pref: List[int] = [1]

    def add(self, num: int) -> None:
        if not (0 <= num <= 100):
            raise ValueError("num out of allowed range [0,100]")
        if num == 0:
            self.pref = [1]
        else:
            self.pref.append(self.pref[-1] * num)  # fits in 32-bit per constraints

    def getProduct(self, k: int) -> int:
        if k <= 0:
            raise ValueError("k must be positive")
        if k >= len(self.pref):
            return 0
        return self.pref[-1] // self.pref[-1 - k]


def run_tests() -> None:
    def header(title: str) -> None:
        print(f"---- {title} ----")

    # Test Case 1: Example
    header("Test Case 1: Example")
    p1 = ProductOfNumbers()
    p1.add(3)
    p1.add(0)
    p1.add(2)
    p1.add(5)
    p1.add(4)
    print(p1.getProduct(2))  # 20
    print(p1.getProduct(3))  # 40
    print(p1.getProduct(4))  # 0
    p1.add(8)
    print(p1.getProduct(2))  # 32

    # Test Case 2: No zeros
    header("Test Case 2: No zeros")
    p2 = ProductOfNumbers()
    p2.add(1)
    p2.add(2)
    p2.add(3)
    p2.add(4)
    print(p2.getProduct(1))  # 4
    print(p2.getProduct(2))  # 12
    print(p2.getProduct(4))  # 24

    # Test Case 3: Multiple zeros and resets
    header("Test Case 3: Multiple zeros")
    p3 = ProductOfNumbers()
    p3.add(0)
    p3.add(9)
    p3.add(9)
    print(p3.getProduct(2))  # 81
    p3.add(0)
    print(p3.getProduct(1))  # 0
    p3.add(7)
    print(p3.getProduct(2))  # 0
    print(p3.getProduct(1))  # 7

    # Test Case 4: Crossing zero
    header("Test Case 4: Crossing zero")
    p4 = ProductOfNumbers()
    p4.add(2)
    p4.add(5)
    p4.add(0)
    p4.add(3)
    p4.add(4)
    print(p4.getProduct(2))  # 12
    print(p4.getProduct(3))  # 0
    print(p4.getProduct(5))  # 0

    # Test Case 5: Mixed segments
    header("Test Case 5: Mixed segments")
    p5 = ProductOfNumbers()
    p5.add(5)
    p5.add(2)
    p5.add(0)
    p5.add(1)
    p5.add(1)
    p5.add(1)
    p5.add(10)
    p5.add(0)
    p5.add(2)
    p5.add(2)
    p5.add(2)
    print(p5.getProduct(1))  # 2
    print(p5.getProduct(2))  # 4
    print(p5.getProduct(3))  # 8
    print(p5.getProduct(4))  # 0


if __name__ == "__main__":
    run_tests()