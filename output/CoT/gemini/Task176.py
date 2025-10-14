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
        return self.prefix_products[-1] // self.prefix_products[-1 - k]


if __name__ == "__main__":
    # Test Case 1: Example from prompt
    print("Test Case 1:")
    p1 = ProductOfNumbers()
    p1.add(3)
    p1.add(0)
    p1.add(2)
    p1.add(5)
    p1.add(4)
    print(f"getProduct(2): {p1.getProduct(2)}")
    print(f"getProduct(3): {p1.getProduct(3)}")
    print(f"getProduct(4): {p1.getProduct(4)}")
    p1.add(8)
    print(f"getProduct(2): {p1.getProduct(2)}")
    print()

    # Test Case 2: Multiple zeros
    print("Test Case 2:")
    p2 = ProductOfNumbers()
    p2.add(1)
    p2.add(2)
    p2.add(0)
    p2.add(4)
    p2.add(5)
    print(f"getProduct(2): {p2.getProduct(2)}")
    p2.add(0)
    p2.add(10)
    print(f"getProduct(1): {p2.getProduct(1)}")
    print()
    
    # Test Case 3: k equals the number of non-zero elements
    print("Test Case 3:")
    p3 = ProductOfNumbers()
    p3.add(5)
    p3.add(6)
    p3.add(7)
    print(f"getProduct(3): {p3.getProduct(3)}")
    print()
    
    # Test Case 4: getProduct(1)
    print("Test Case 4:")
    p4 = ProductOfNumbers()
    p4.add(100)
    p4.add(50)
    print(f"getProduct(1): {p4.getProduct(1)}")
    print(f"getProduct(2): {p4.getProduct(2)}")
    print()
    
    # Test Case 5: k spans across a zero
    print("Test Case 5:")
    p5 = ProductOfNumbers()
    p5.add(1)
    p5.add(2)
    p5.add(3)
    p5.add(0)
    p5.add(4)
    p5.add(5)
    p5.add(6)
    print(f"getProduct(3): {p5.getProduct(3)}")
    print(f"getProduct(4): {p5.getProduct(4)}")
    print()