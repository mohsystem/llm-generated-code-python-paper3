
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
    # Test case 1: Example from problem
    test1 = Task176()
    test1.add(3)
    test1.add(0)
    test1.add(2)
    test1.add(5)
    test1.add(4)
    print(test1.getProduct(2))  # Expected: 20
    print(test1.getProduct(3))  # Expected: 40
    print(test1.getProduct(4))  # Expected: 0
    test1.add(8)
    print(test1.getProduct(2))  # Expected: 32
    
    # Test case 2: All non-zero
    test2 = Task176()
    test2.add(2)
    test2.add(3)
    test2.add(4)
    print(test2.getProduct(2))  # Expected: 12
    print(test2.getProduct(3))  # Expected: 24
    
    # Test case 3: Multiple zeros
    test3 = Task176()
    test3.add(5)
    test3.add(0)
    test3.add(0)
    test3.add(6)
    print(test3.getProduct(1))  # Expected: 6
    
    # Test case 4: Single element
    test4 = Task176()
    test4.add(7)
    print(test4.getProduct(1))  # Expected: 7
    
    # Test case 5: Zero then non-zero
    test5 = Task176()
    test5.add(1)
    test5.add(2)
    test5.add(0)
    test5.add(3)
    test5.add(4)
    print(test5.getProduct(2))  # Expected: 12
    print(test5.getProduct(3))  # Expected: 0
