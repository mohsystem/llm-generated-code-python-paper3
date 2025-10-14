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


def run_tests():
    # Test 1: Example provided
    pon = ProductOfNumbers()
    pon.add(3)
    pon.add(0)
    pon.add(2)
    pon.add(5)
    pon.add(4)
    out1 = []
    out1.append(pon.getProduct(2))  # 20
    out1.append(pon.getProduct(3))  # 40
    out1.append(pon.getProduct(4))  # 0
    pon.add(8)
    out1.append(pon.getProduct(2))  # 32
    print(out1)

    # Test 2: No zeros
    pon = ProductOfNumbers()
    pon.add(1)
    pon.add(2)
    pon.add(3)
    pon.add(4)
    out2 = []
    out2.append(pon.getProduct(1))  # 4
    out2.append(pon.getProduct(3))  # 24
    out2.append(pon.getProduct(4))  # 24
    print(out2)

    # Test 3: Zeros resetting
    pon = ProductOfNumbers()
    pon.add(0)
    pon.add(0)
    pon.add(7)
    pon.add(3)
    out3 = []
    out3.append(pon.getProduct(1))  # 3
    out3.append(pon.getProduct(2))  # 21
    print(out3)

    # Test 4: Long k equals length
    pon = ProductOfNumbers()
    for _ in range(5):
        pon.add(2)
    out4 = [pon.getProduct(5)]  # 32
    print(out4)

    # Test 5: Mix with ones and zero
    pon = ProductOfNumbers()
    pon.add(1)
    pon.add(1)
    pon.add(1)
    pon.add(1)
    pon.add(0)
    pon.add(10)
    out5 = []
    out5.append(pon.getProduct(1))  # 10
    out5.append(pon.getProduct(2))  # 0
    pon.add(2)
    out5.append(pon.getProduct(2))  # 20
    print(out5)


if __name__ == "__main__":
    run_tests()