class ProductOfNumbers:

    def __init__(self):
        self.prefix_products = [1]

    def add(self, num: int) -> None:
        if num == 0:
            self.prefix_products = [1]
        else:
            self.prefix_products.append(self.prefix_products[-1] * num)

    def getProduct(self, k: int) -> int:
        n = len(self.prefix_products)
        if k >= n:
            return 0
        return self.prefix_products[-1] // self.prefix_products[n - 1 - k]

if __name__ == '__main__':
    # Test Case 1
    pon1 = ProductOfNumbers()
    pon1.add(3)
    pon1.add(0)
    pon1.add(2)
    pon1.add(5)
    pon1.add(4)
    print(pon1.getProduct(2)) # 20
    print(pon1.getProduct(3)) # 40
    print(pon1.getProduct(4)) # 0
    pon1.add(8)
    print(pon1.getProduct(2)) # 32
    print()

    # Test Case 2
    pon2 = ProductOfNumbers()
    pon2.add(1)
    pon2.add(2)
    pon2.add(3)
    pon2.add(4)
    pon2.add(5)
    print(pon2.getProduct(1)) # 5
    print(pon2.getProduct(2)) # 20
    print(pon2.getProduct(5)) # 120
    print()

    # Test Case 3
    pon3 = ProductOfNumbers()
    pon3.add(0)
    pon3.add(10)
    pon3.add(20)
    print(pon3.getProduct(1)) # 20
    print(pon3.getProduct(2)) # 200
    print(pon3.getProduct(3)) # 0
    print()

    # Test Case 4
    pon4 = ProductOfNumbers()
    pon4.add(5)
    pon4.add(6)
    pon4.add(0)
    pon4.add(7)
    pon4.add(0)
    pon4.add(8)
    pon4.add(9)
    print(pon4.getProduct(1)) # 9
    print(pon4.getProduct(2)) # 72
    print(pon4.getProduct(3)) # 0
    print()

    # Test Case 5
    pon5 = ProductOfNumbers()
    pon5.add(42)
    print(pon5.getProduct(1)) # 42
    pon5.add(0)
    print(pon5.getProduct(1)) # 0
    pon5.add(1)
    print(pon5.getProduct(1)) # 1
    print(pon5.getProduct(2)) # 0
    print()