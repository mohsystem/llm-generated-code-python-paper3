import math

def dig_pow(n, p):
    """
    Finds a positive integer k, if it exists, such that the sum of the digits of n
    raised to consecutive powers starting from p is equal to k * n.
    :param n: a positive integer.
    :param p: a positive integer.
    :return: a positive integer k, or -1 if no such k exists.
    """
    n_str = str(n)
    total_sum = 0
    for i, digit_char in enumerate(n_str):
        digit = int(digit_char)
        total_sum += math.pow(digit, p + i)
    
    if total_sum % n == 0:
        return int(total_sum / n)
    else:
        return -1

if __name__ == '__main__':
    print(f"n = 89, p = 1 --> {dig_pow(89, 1)}")
    print(f"n = 92, p = 1 --> {dig_pow(92, 1)}")
    print(f"n = 695, p = 2 --> {dig_pow(695, 2)}")
    print(f"n = 46288, p = 3 --> {dig_pow(46288, 3)}")
    print(f"n = 135, p = 1 --> {dig_pow(135, 1)}")