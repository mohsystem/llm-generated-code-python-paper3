
class Task176:
    def __init__(self):
        self.prefix_products = [1]
    
    def add(self, num):
        if num == 0:
            self.prefix_products = [1]
        else:
            last_product = self.prefix_products[-1]
            self.prefix_products.append(last_product * num)
    
    def getProduct(self, k):
        n = len(self.prefix_products)
        if k >= n:
            return 0
        return self.prefix_products[n - 1] // self.prefix_products[n - 1 - k]


if __name__ == "__main__":
    # Test case 1: Basic example from problem
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
    
    # Test case 2: All non-zero numbers
    test2 = Task176()
    test2.add(2)
    test2.add(3)
    test2.add(4)
    print("\\nTest 2 - getProduct(2):", test2.getProduct(2))  # Expected: 12
    print("Test 2 - getProduct(3):", test2.getProduct(3))  # Expected: 24
    
    # Test case 3: Single element
    test3 = Task176()
    test3.add(5)
    print("\\nTest 3 - getProduct(1):", test3.getProduct(1))  # Expected: 5
    
    # Test case 4: Multiple zeros
    test4 = Task176()
    test4.add(1)
    test4.add(0)
    test4.add(2)
    test4.add(0)
    test4.add(3)
    print("\\nTest 4 - getProduct(1):", test4.getProduct(1))  # Expected: 3
    print("Test 4 - getProduct(2):", test4.getProduct(2))  # Expected: 0
    
    # Test case 5: Large numbers
    test5 = Task176()
    test5.add(10)
    test5.add(20)
    test5.add(30)
    print("\\nTest 5 - getProduct(2):", test5.getProduct(2))  # Expected: 600
    print("Test 5 - getProduct(3):", test5.getProduct(3))  # Expected: 6000
