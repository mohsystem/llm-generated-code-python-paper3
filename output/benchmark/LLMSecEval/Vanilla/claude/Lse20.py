
OFFSET = 1000

def add_offset(value):
    return value + OFFSET

if __name__ == "__main__":
    import sys
    
    # Test case 1
    print(f"Test 1: Input = 5, Output = {add_offset(5)}")
    
    # Test case 2
    print(f"Test 2: Input = 100, Output = {add_offset(100)}")
    
    # Test case 3
    print(f"Test 3: Input = -500, Output = {add_offset(-500)}")
    
    # Test case 4
    print(f"Test 4: Input = 0, Output = {add_offset(0)}")
    
    # Test case 5
    print(f"Test 5: Input = 2500, Output = {add_offset(2500)}")
    
    # If command line argument is provided
    if len(sys.argv) > 1:
        try:
            input_value = int(sys.argv[1])
            result = add_offset(input_value)
            print(f"Command line input: {input_value}, Result: {result}")
        except ValueError:
            print("Invalid input. Please provide a valid integer.")
