
from typing import List

class ProductOfNumbers:
    def __init__(self):
        self.prefix_products: List[int] = [1]
    
    def add(self, num: int) -> None:
        if not isinstance(num, int) or num < 0 or num > 100:
            raise ValueError("Number must be an integer between 0 and 100")
        
        if num == 0:
            self.prefix_products = [1]
        else:
            last_product = self.prefix_products[-1]
            self.prefix_products.append(last_product * num)
    
    def getProduct(self, k: int) -> int:
        if not isinstance(k, int) or k < 1 or k > 40000:
            raise ValueError("k must be an integer between 1 and 40000")
        
        n = len(self.prefix_products)
        if k >= n:
            return 0
        
        return self.prefix_products[-1] // self.prefix_products[-1 - k]


def main():
    # Test case 1: Example from problem
    test1 = ProductOfNumbers()
    test1.add(3)
    test1.add(0)
    test1.add(2)
    test1.add(5)
    test1.add(4)
    print(test1.getProduct(2))  # 20
    print(test1.getProduct(3))  # 40
    print(test1.getProduct(4))  # 0
    test1.add(8)
    print(test1.getProduct(2))  # 32
    
    # Test case 2: All non-zero
    test2 = ProductOfNumbers()
    test2.add(2)
    test2.add(3)
    test2.add(4)
    print(test2.getProduct(2))  # 12
    
    # Test case 3: Multiple zeros
    test3 = ProductOfNumbers()
    test3.add(1)
    test3.add(0)
    test3.add(0)
    test3.add(5)
    print(test3.getProduct(1))  # 5
    
    # Test case 4: Single element
    test4 = ProductOfNumbers()
    test4.add(7)
    print(test4.getProduct(1))  # 7
    
    # Test case 5: Large numbers
    test5 = ProductOfNumbers()
    test5.add(100)
    test5.add(100)
    test5.add(1)
    print(test5.getProduct(3))  # 10000


if __name__ == "__main__":
    main()
