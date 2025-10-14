from typing import List

class ProductOfNumbers:

    def __init__(self):
        self.prefix_products: List[int] = [1]

    def add(self, num: int) -> None:
        if num == 0:
            self.prefix_products = [1]
        else:
            self.prefix_products.append(self.prefix_products[-1] * num)

    def getProduct(self, k: int) -> int:
        n = len(self.prefix_products)
        if k >= n:
            return 0
        return self.prefix_products[-1] // self.prefix_products[-1 - k]

if __name__ == '__main__':
    # Test Case 1 (from example)
    print("--- Test Case 1 ---")
    pon1 = ProductOfNumbers()
    pon1.add(3)
    pon1.add(0)
    pon1.add(2)
    pon1.add(5)
    pon1.add(4)
    print(f"getProduct(2): {pon1.getProduct(2)}") # Expected: 20
    print(f"getProduct(3): {pon1.getProduct(3)}") # Expected: 40
    print(f"getProduct(4): {pon1.getProduct(4)}") # Expected: 0
    pon1.add(8)
    print(f"getProduct(2): {pon1.getProduct(2)}") # Expected: 32

    # Test Case 2
    print("\n--- Test Case 2 ---")
    pon2 = ProductOfNumbers()
    pon2.add(5)
    pon2.add(10)
    pon2.add(2)
    print(f"getProduct(3): {pon2.getProduct(3)}") # Expected: 100

    # Test Case 3
    print("\n--- Test Case 3 ---")
    pon3 = ProductOfNumbers()
    pon3.add(1)
    pon3.add(1)
    pon3.add(0)
    pon3.add(1)
    pon3.add(1)
    print(f"getProduct(2): {pon3.getProduct(2)}") # Expected: 1
    print(f"getProduct(3): {pon3.getProduct(3)}") # Expected: 0

    # Test Case 4
    print("\n--- Test Case 4 ---")
    pon4 = ProductOfNumbers()
    pon4.add(7)
    print(f"getProduct(1): {pon4.getProduct(1)}") # Expected: 7

    # Test Case 5
    print("\n--- Test Case 5 ---")
    pon5 = ProductOfNumbers()
    pon5.add(4)
    pon5.add(0)
    pon5.add(9)
    pon5.add(8)
    pon5.add(0)
    pon5.add(2)
    print(f"getProduct(1): {pon5.getProduct(1)}") # Expected: 2
    print(f"getProduct(2): {pon5.getProduct(2)}") # Expected: 0