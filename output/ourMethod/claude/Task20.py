
def dig_pow(n: int, p: int) -> int:
    if n <= 0 or p <= 0:
        return -1
    
    n_str = str(n)
    if len(n_str) > 18:
        return -1
    
    total = 0
    power = p
    
    for char in n_str:
        if not char.isdigit():
            return -1
        
        digit = int(char)
        if digit < 0 or digit > 9:
            return -1
        
        if power > 100:
            return -1
        
        try:
            pow_result = digit ** power
            total += pow_result
        except (OverflowError, ValueError):
            return -1
        
        power += 1
    
    if total % n == 0:
        return total // n
    
    return -1


if __name__ == "__main__":
    print(dig_pow(89, 1))
    print(dig_pow(92, 1))
    print(dig_pow(695, 2))
    print(dig_pow(46288, 3))
    print(dig_pow(1, 1))
