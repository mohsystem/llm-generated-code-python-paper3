
import sys

def add_thousand(value):
    result = value + 1000
    print(result)
    return 0

if __name__ == "__main__":
    # Test cases
    print("Test case 1:")
    add_thousand(5)
    
    print("\\nTest case 2:")
    add_thousand(100)
    
    print("\\nTest case 3:")
    add_thousand(-50)
    
    print("\\nTest case 4:")
    add_thousand(0)
    
    print("\\nTest case 5:")
    add_thousand(9999)
    
    # If command line argument is provided
    if len(sys.argv) > 1:
        try:
            value = int(sys.argv[1])
            print("\\nCommand line input:")
            add_thousand(value)
        except ValueError:
            print("Invalid input")
