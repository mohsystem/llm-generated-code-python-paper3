
import sys

def add_thousand(value):
    return value + 1000

if __name__ == "__main__":
    # Test cases
    print("Test 1:", add_thousand(500))      # Expected: 1500
    print("Test 2:", add_thousand(0))        # Expected: 1000
    print("Test 3:", add_thousand(-100))     # Expected: 900
    print("Test 4:", add_thousand(2500))     # Expected: 3500
    print("Test 5:", add_thousand(-1000))    # Expected: 0
    
    # Command line argument handling
    if len(sys.argv) > 1:
        try:
            value = int(sys.argv[1])
            print("Command line result:", add_thousand(value))
        except ValueError:
            print("Invalid input. Please provide a valid integer.", file=sys.stderr)
