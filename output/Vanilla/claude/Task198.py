
import random

def rand7():
    """Simulating rand7() API"""
    return random.randint(1, 7)

def rand10():
    while True:
        # Generate a number in range [1, 49]
        row = rand7()
        col = rand7()
        num = (row - 1) * 7 + col
        
        # Only use numbers 1-40 to ensure uniformity
        if num <= 40:
            return (num - 1) % 10 + 1

def main():
    # Test case 1: n = 1
    print(f"Test 1 (n=1): {[rand10() for _ in range(1)]}")
    
    # Test case 2: n = 2
    print(f"Test 2 (n=2): {[rand10() for _ in range(2)]}")
    
    # Test case 3: n = 3
    print(f"Test 3 (n=3): {[rand10() for _ in range(3)]}")
    
    # Test case 4: n = 5
    print(f"Test 4 (n=5): {[rand10() for _ in range(5)]}")
    
    # Test case 5: n = 10
    print(f"Test 5 (n=10): {[rand10() for _ in range(10)]}")

if __name__ == "__main__":
    main()
