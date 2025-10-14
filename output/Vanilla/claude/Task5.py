
def persistence(num):
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
    print(f"Input: 39, Output: {persistence(39)}")
    print(f"Input: 999, Output: {persistence(999)}")
    print(f"Input: 4, Output: {persistence(4)}")
    print(f"Input: 25, Output: {persistence(25)}")
    print(f"Input: 77, Output: {persistence(77)}")
