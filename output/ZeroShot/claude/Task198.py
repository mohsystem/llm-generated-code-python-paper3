
import random

class Task198:
    @staticmethod
    def rand7():
        """Simulated rand7() function for testing"""
        return random.randint(1, 7)
    
    @staticmethod
    def rand10():
        result = 0
        while True:
            # Generate a number in range [1, 49]
            row = Task198.rand7()
            col = Task198.rand7()
            result = (row - 1) * 7 + col
            if result <= 40:  # Reject numbers > 40 to maintain uniform distribution
                break
        
        # Map [1, 40] to [1, 10]
        return (result - 1) % 10 + 1
    
    @staticmethod
    def test_rand10(n):
        results = []
        for _ in range(n):
            results.append(Task198.rand10())
        return results

if __name__ == "__main__":
    # Test case 1
    result1 = Task198.test_rand10(1)
    print(f"Test 1 (n=1): {result1}")
    
    # Test case 2
    result2 = Task198.test_rand10(2)
    print(f"Test 2 (n=2): {result2}")
    
    # Test case 3
    result3 = Task198.test_rand10(3)
    print(f"Test 3 (n=3): {result3}")
    
    # Test case 4
    result4 = Task198.test_rand10(5)
    print(f"Test 4 (n=5): {result4}")
    
    # Test case 5
    result5 = Task198.test_rand10(10)
    print(f"Test 5 (n=10): {result5}")
