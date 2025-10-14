class ProductOfNumbers:
    def __init__(self):
        self.prefix = [1]

    def add(self, num: int) -> None:
        if num == 0:
            self.prefix = [1]
        else:
            self.prefix.append(self.prefix[-1] * num)

    def getProduct(self, k: int) -> int:
        if k >= len(self.prefix):
            return 0
        return self.prefix[-1] // self.prefix[-1 - k]


def main():
    # Test case 1 (sample)
    p1 = ProductOfNumbers()
    p1.add(3); p1.add(0); p1.add(2); p1.add(5); p1.add(4)
    print(p1.getProduct(2))
    print(p1.getProduct(3))
    print(p1.getProduct(4))
    p1.add(8)
    print(p1.getProduct(2))

    # Test case 2
    p2 = ProductOfNumbers()
    p2.add(1); p2.add(2); p2.add(3); p2.add(4)
    print(p2.getProduct(1))
    print(p2.getProduct(4))

    # Test case 3
    p3 = ProductOfNumbers()
    p3.add(0); p3.add(0); p3.add(2); p3.add(3)
    print(p3.getProduct(1))
    print(p3.getProduct(3))

    # Test case 4
    p4 = ProductOfNumbers()
    p4.add(10); p4.add(10); p4.add(10)
    print(p4.getProduct(2))
    print(p4.getProduct(3))

    # Test case 5
    p5 = ProductOfNumbers()
    p5.add(100); p5.add(0); p5.add(100); p5.add(100)
    print(p5.getProduct(1))
    print(p5.getProduct(2))
    print(p5.getProduct(3))


if __name__ == "__main__":
    main()