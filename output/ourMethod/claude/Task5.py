
def persistence(num: int) -> int:
    if not isinstance(num, int) or num < 0:
        raise ValueError("Input must be a non-negative integer")
    
    if num < 10:
        return 0
    
    count = 0
    current = num
    
    while current >= 10:
        product = 1
        while current > 0:
            product *= current % 10
            current //= 10
        current = product
        count += 1
        
        if count > 100:
            raise RuntimeError("Exceeded maximum iterations")
    
    return count


def main():
    print(f"Test 1: persistence(39) = {persistence(39)}")
    print(f"Test 2: persistence(999) = {persistence(999)}")
    print(f"Test 3: persistence(4) = {persistence(4)}")
    print(f"Test 4: persistence(25) = {persistence(25)}")
    print(f"Test 5: persistence(0) = {persistence(0)}")


if __name__ == "__main__":
    main()
