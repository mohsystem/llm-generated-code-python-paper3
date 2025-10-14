
class Task176:
    def __init__(self):
        self.prefix_products = [1]  # Initial prefix product
    
    def add(self, num):
        if num == 0:
            # Reset the prefix products when 0 is encountered
            self.prefix_products = [1]
        else:
            # Add the product of last prefix and current number
            last_product = self.prefix_products[-1]
            self.prefix_products.append(last_product * num)
    
    def getProduct(self, k):
        n = len(self.prefix_products)
        # If k is greater than or equal to the size, it means we crossed a zero
        if k >= n:
            return 0
        # Product of last k numbers = prefix_products[n-1] / prefix_products[n-1-k]
        return self.prefix_products[n - 1] // self.prefix_products[n - 1 - k]


if __name__ == "__main__":
    # Test case 1: Example from prompt
    test1 = Task176()
    test1.add(3)
    test1.add(0)
    test1.add(2)
    test1.add(5)
    test1.add(4)
    print("Test 1 - getProduct(2):", test1.getProduct(2))  # Expected: 20
    print("Test 1 - getProduct(3):", test1.getProduct(3))  # Expected: 40
    print("Test 1 - getProduct(4):", test1.getProduct(4))  # Expected: 0
    test1.add(8)
    print("Test 1 - getProduct(2):", test1.getProduct(2))  # Expected: 32
    
    # Test case 2: No zeros
    test2 = Task176()
    test2.add(2)
    test2.add(3)
    test2.add(4)
    print("\\nTest 2 - getProduct(2):", test2.getProduct(2))  # Expected: 12
    print("Test 2 - getProduct(3):", test2.getProduct(3))  # Expected: 24
    
    # Test case 3: Multiple zeros
    test3 = Task176()
    test3.add(1)
    test3.add(0)
    test3.add(5)
    test3.add(0)
    test3.add(3)
    print("\\nTest 3 - getProduct(1):", test3.getProduct(1))  # Expected: 3
    
    # Test case 4: All ones
    test4 = Task176()
    test4.add(1)
    test4.add(1)
    test4.add(1)
    print("\\nTest 4 - getProduct(3):", test4.getProduct(3))  # Expected: 1
    
    # Test case 5: Large numbers
    test5 = Task176()
    test5.add(10)
    test5.add(10)
    test5.add(10)
    print("\\nTest 5 - getProduct(2):", test5.getProduct(2))  # Expected: 100
    print("Test 5 - getProduct(3):", test5.getProduct(3))  # Expected: 1000
