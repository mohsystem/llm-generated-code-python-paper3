
import secrets
import sys

def generate_and_sum():
    """\n    Generate three random integers larger than 1000 and compute their sum.\n    Uses secrets module for cryptographically secure random number generation.\n    """
    # Use secrets.randbelow for cryptographically secure random generation
    # Generate numbers in range 1001 to sys.maxsize // 3 to prevent overflow
    max_value = sys.maxsize // 3
    
    # Generate three random integers larger than 1000
    a = 1001 + secrets.randbelow(max_value - 1001)
    b = 1001 + secrets.randbelow(max_value - 1001)
    c = 1001 + secrets.randbelow(max_value - 1001)
    
    # Print the three integers
    print(f"a : {a}")
    print(f"b : {b}")
    print(f"c : {c}")
    
    # Add the three integers with overflow check
    try:
        sum_result = a + b + c
        # Validate sum is within expected range
        if sum_result < 0:
            print("Error: Sum overflow detected", file=sys.stderr)
            return
        
        # Print the sum
        print(f"sum: {sum_result}")
        print(f"sum2: {sum_result}")
    except OverflowError:
        print("Error: Sum overflow detected", file=sys.stderr)

def main():
    """Main function with test cases"""
    # Test case 1
    print("Test case 1:")
    generate_and_sum()
    print()
    
    # Test case 2
    print("Test case 2:")
    generate_and_sum()
    print()
    
    # Test case 3
    print("Test case 3:")
    generate_and_sum()
    print()
    
    # Test case 4
    print("Test case 4:")
    generate_and_sum()
    print()
    
    # Test case 5
    print("Test case 5:")
    generate_and_sum()

if __name__ == "__main__":
    main()
