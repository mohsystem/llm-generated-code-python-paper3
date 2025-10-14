
def persistence(num):
    # Input validation: ensure num is positive
    if num < 0:
        raise ValueError("Number must be positive")
    
    # Base case: single digit
    if num < 10:
        return 0
    
    count = 0
    
    # Continue until we reach a single digit
    while num >= 10:
        product = 1
        
        # Multiply all digits
        for digit in str(num):
            product *= int(digit)
        
        num = product
        count += 1
    
    return count


if __name__ == "__main__":
    # Test cases
    print(f"Test 1: persistence(39) = {persistence(39)} (expected: 3)")
    print(f"Test 2: persistence(999) = {persistence(999)} (expected: 4)")
    print(f"Test 3: persistence(4) = {persistence(4)} (expected: 0)")
    print(f"Test 4: persistence(25) = {persistence(25)} (expected: 2)")
    print(f"Test 5: persistence(10) = {persistence(10)} (expected: 1)")
