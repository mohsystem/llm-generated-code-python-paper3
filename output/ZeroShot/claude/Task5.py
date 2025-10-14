
def persistence(num):
    if num < 10:
        return 0
    
    count = 0
    
    while num >= 10:
        product = 1
        while num > 0:
            product *= num % 10
            num //= 10
        num = product
        count += 1
    
    return count


if __name__ == "__main__":
    # Test cases
    print(f"Test 1: persistence(39) = {persistence(39)} (Expected: 3)")
    print(f"Test 2: persistence(999) = {persistence(999)} (Expected: 4)")
    print(f"Test 3: persistence(4) = {persistence(4)} (Expected: 0)")
    print(f"Test 4: persistence(25) = {persistence(25)} (Expected: 2)")
    print(f"Test 5: persistence(77) = {persistence(77)} (Expected: 4)")
