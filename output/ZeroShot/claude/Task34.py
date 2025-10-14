
def is_narcissistic(number):
    num_str = str(number)
    num_digits = len(num_str)
    sum_of_powers = sum(int(digit) ** num_digits for digit in num_str)
    return sum_of_powers == number


if __name__ == "__main__":
    # Test cases
    print(f"Test 1 - Input: 153, Output: {is_narcissistic(153)}")
    print(f"Test 2 - Input: 1652, Output: {is_narcissistic(1652)}")
    print(f"Test 3 - Input: 9474, Output: {is_narcissistic(9474)}")
    print(f"Test 4 - Input: 9475, Output: {is_narcissistic(9475)}")
    print(f"Test 5 - Input: 9, Output: {is_narcissistic(9)}")
