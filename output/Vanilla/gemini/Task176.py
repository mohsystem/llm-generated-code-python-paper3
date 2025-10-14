class ProductOfNumbers:

    def __init__(self):
        # We store prefix products since the last zero.
        # Start with 1 to handle division easily.
        self.prefix_products = [1]

    def add(self, num: int) -> None:
        if num == 0:
            # If a zero is added, the product of any range including it is 0.
            # We reset the list to start a new sequence of products.
            self.prefix_products = [1]
        else:
            # Append the product of the new number and the previous prefix product.
            self.prefix_products.append(self.prefix_products[-1] * num)

    def getProduct(self, k: int) -> int:
        n = len(self.prefix_products)
        # If k is larger than the number of non-zero elements we are tracking,
        # it means the product must include a zero encountered earlier.
        if k >= n:
            return 0
        
        # The product of the last k elements is the last prefix product
        # divided by the prefix product from k steps ago.
        last_product = self.prefix_products[-1]
        product_before_k = self.prefix_products[-1 - k]
        return last_product // product_before_k

class Task176:
    @staticmethod
    def run_tests():
        # Test Case 1 (from example)
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

        # Test Case 2: No zeros
        print("Test Case 2:")
        p2 = ProductOfNumbers()
        p2.add(1)
        p2.add(2)
        p2.add(3)
        p2.add(4)
        print(f"getProduct(1): {p2.getProduct(1)}")
        print(f"getProduct(4): {p2.getProduct(4)}")
        print()

        # Test Case 3: Starts with zero
        print("Test Case 3:")
        p3 = ProductOfNumbers()
        p3.add(0)
        p3.add(5)
        p3.add(10)
        print(f"getProduct(1): {p3.getProduct(1)}")
        print(f"getProduct(2): {p3.getProduct(2)}")
        print(f"getProduct(3): {p3.getProduct(3)}")
        print()

        # Test Case 4: Multiple zeros
        print("Test Case 4:")
        p4 = ProductOfNumbers()
        p4.add(5)
        p4.add(6)
        p4.add(0)
        p4.add(7)
        p4.add(0)
        p4.add(8)
        p4.add(9)
        print(f"getProduct(1): {p4.getProduct(1)}")
        print(f"getProduct(2): {p4.getProduct(2)}")
        print(f"getProduct(3): {p4.getProduct(3)}")
        print()

        # Test Case 5: k equals the number of elements
        print("Test Case 5:")
        p5 = ProductOfNumbers()
        p5.add(10)
        p5.add(20)
        p5.add(30)
        print(f"getProduct(3): {p5.getProduct(3)}")
        print()

if __name__ == "__main__":
    Task176.run_tests()