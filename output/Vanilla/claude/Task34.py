
def is_narcissistic(number):
    num_str = str(number)
    num_digits = len(num_str)
    sum_of_powers = sum(int(digit) ** num_digits for digit in num_str)
    return sum_of_powers == number

# Test cases
if __name__ == "__main__":
    print("Test 1: is_narcissistic(153) =", is_narcissistic(153))  # True
    print("Test 2: is_narcissistic(1652) =", is_narcissistic(1652))  # False
    print("Test 3: is_narcissistic(9) =", is_narcissistic(9))  # True
    print("Test 4: is_narcissistic(9474) =", is_narcissistic(9474))  # True
    print("Test 5: is_narcissistic(1634) =", is_narcissistic(1634))  # True
