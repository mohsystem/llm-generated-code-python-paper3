def dig_pow(n, p):
    """
    Finds a positive integer k, if it exists, such that the sum of the digits of n
    raised to consecutive powers starting from p is equal to k * n.

    :param n: A positive integer.
    :param p: A positive integer.
    :return: The integer k if found, otherwise -1.
    """
    s = str(n)
    total = sum(int(digit) ** (p + i) for i, digit in enumerate(s))
    
    if total % n == 0:
        return total // n
    else:
        return -1

if __name__ == '__main__':
    # Test cases
    print(f"n=89, p=1 -> {dig_pow(89, 1)}")
    print(f"n=92, p=1 -> {dig_pow(92, 1)}")
    print(f"n=695, p=2 -> {dig_pow(695, 2)}")
    print(f"n=46288, p=3 -> {dig_pow(46288, 3)}")
    print(f"n=135, p=1 -> {dig_pow(135, 1)}")