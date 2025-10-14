class ProductOfNumbers:
    def __init__(self):
        self.prefix = [1]  # sentinel for products since last zero

    def add(self, num: int) -> None:
        if num == 0:
            self.prefix = [1]
            return
        self.prefix.append(self.prefix[-1] * num)

    def getProduct(self, k: int) -> int:
        if k < 0:
            raise ValueError("k must be non-negative")
        if k >= len(self.prefix):
            return 0
        return self.prefix[-1] // self.prefix[-1 - k]


def main():
    # Test case 1: Example from prompt
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

    # Test case 2: No zeros
    p2 = ProductOfNumbers()
    p2.add(1)
    p2.add(2)
    p2.add(3)
    p2.add(4)
    print(p2.getProduct(4))  # 24

    # Test case 3: Multiple zeros with short queries
    p3 = ProductOfNumbers()
    p3.add(0)
    p3.add(7)
    p3.add(0)
    p3.add(10)
    print(p3.getProduct(1))  # 10
    print(p3.getProduct(2))  # 0

    # Test case 4: Larger k within segment
    p4 = ProductOfNumbers()
    p4.add(2)
    p4.add(2)
    p4.add(2)
    p4.add(2)
    p4.add(2)
    print(p4.getProduct(5))  # 32

    # Test case 5: Zero boundary checks
    p5 = ProductOfNumbers()
    p5.add(9)
    p5.add(9)
    p5.add(0)
    p5.add(9)
    p5.add(9)
    p5.add(9)
    print(p5.getProduct(3))  # 729
    print(p5.getProduct(4))  # 0


if __name__ == "__main__":
    main()