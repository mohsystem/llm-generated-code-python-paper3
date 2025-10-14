
import random

def rand7() -> int:
    """Simulated rand7() for testing purposes"""
    return random.randint(1, 7)

def rand10() -> int:
    """Generate uniform random integer in range [1, 10] using rand7()"""
    while True:
        row = rand7()
        col = rand7()
        idx = (row - 1) * 7 + col
        if idx <= 40:
            return ((idx - 1) % 10) + 1

def main() -> None:
    # Test case 1: n = 1
    result = [rand10() for _ in range(1)]
    print(f"Test 1: {result}")
    
    # Test case 2: n = 2
    result = [rand10() for _ in range(2)]
    print(f"Test 2: {result}")
    
    # Test case 3: n = 3
    result = [rand10() for _ in range(3)]
    print(f"Test 3: {result}")
    
    # Test case 4: n = 5
    result = [rand10() for _ in range(5)]
    print(f"Test 4: {result}")
    
    # Test case 5: n = 10
    result = [rand10() for _ in range(10)]
    print(f"Test 5: {result}")

if __name__ == "__main__":
    main()
