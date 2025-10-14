
def find_gcd(a, b):
    a = abs(a)
    b = abs(b)
    
    while b != 0:
        temp = b
        b = a % b
        a = temp
    return a

if __name__ == "__main__":
    # Test case 1
    print(f"GCD of 48 and 18: {find_gcd(48, 18)}")
    
    # Test case 2
    print(f"GCD of 100 and 50: {find_gcd(100, 50)}")
    
    # Test case 3
    print(f"GCD of 17 and 19: {find_gcd(17, 19)}")
    
    # Test case 4
    print(f"GCD of 270 and 192: {find_gcd(270, 192)}")
    
    # Test case 5
    print(f"GCD of 1071 and 462: {find_gcd(1071, 462)}")
