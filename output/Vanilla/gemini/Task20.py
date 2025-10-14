def dig_pow(n, p):
    s = str(n)
    total_sum = 0
    for i, digit_char in enumerate(s):
        total_sum += int(digit_char) ** (p + i)
    
    if total_sum % n == 0:
        return total_sum // n
    else:
        return -1

if __name__ == '__main__':
    print(f"n=89, p=1 -> {dig_pow(89, 1)}")
    print(f"n=92, p=1 -> {dig_pow(92, 1)}")
    print(f"n=695, p=2 -> {dig_pow(695, 2)}")
    print(f"n=46288, p=3 -> {dig_pow(46288, 3)}")
    print(f"n=114, p=3 -> {dig_pow(114, 3)}")