
import random

class Task198:
    @staticmethod
    def rand7():
        """Simulated rand7() API"""
        return random.randint(1, 7)
    
    @staticmethod
    def rand10():
        """rand10() implementation using rejection sampling"""
        while True:
            # Generate number in range [0, 48]
            num = (Task198.rand7() - 1) * 7 + (Task198.rand7() - 1)
            
            # Only accept numbers in range [0, 39] for uniform distribution
            if num < 40:
                return (num % 10) + 1
            # Reject and retry if num >= 40
    
    @staticmethod
    def test_rand10(n):
        """Test function"""
        results = []
        for _ in range(n):
            results.append(Task198.rand10())
        return results

if __name__ == "__main__":
    # Test case 1
    test1 = Task198.test_rand10(1)
    print(f"Test 1: {test1}")
    
    # Test case 2
    test2 = Task198.test_rand10(2)
    print(f"Test 2: {test2}")
    
    # Test case 3
    test3 = Task198.test_rand10(3)
    print(f"Test 3: {test3}")
    
    # Test case 4
    test4 = Task198.test_rand10(5)
    print(f"Test 4: {test4}")
    
    # Test case 5
    test5 = Task198.test_rand10(10)
    print(f"Test 5: {test5}")
