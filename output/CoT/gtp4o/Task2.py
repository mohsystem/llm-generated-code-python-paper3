# Chain-of-Through process in code generation:
# 1) Problem understanding: Format 10 digits (0-9) into "(XXX) XXX-XXXX".
# 2) Security requirements: Validate type, length, and value range.
# 3) Secure coding generation: Defensive checks and safe string construction.
# 4) Code review: Ensure no index errors, clear exceptions.
# 5) Secure code output: Final validated function with tests.

def create_phone_number(numbers):
    if numbers is None:
        raise ValueError("Input list is None.")
    if not isinstance(numbers, (list, tuple)):
        raise ValueError("Input must be a list or tuple of integers.")
    if len(numbers) != 10:
        raise ValueError("Input must contain exactly 10 integers.")
    for n in numbers:
        if not isinstance(n, int):
            raise ValueError("All elements must be integers.")
        if n < 0 or n > 9:
            raise ValueError("All integers must be in the range 0-9.")
    return f"({numbers[0]}{numbers[1]}{numbers[2]}) {numbers[3]}{numbers[4]}{numbers[5]}-{numbers[6]}{numbers[7]}{numbers[8]}{numbers[9]}"

if __name__ == "__main__":
    # 5 test cases
    tests = [
        [1,2,3,4,5,6,7,8,9,0],
        [0,1,2,3,4,5,6,7,8,9],
        [0,1,2,3,4,5,6,7,8],      # invalid length
        [-1,1,2,3,4,5,6,7,8,9],  # invalid value
        None                      # None input
    ]
    for i, t in enumerate(tests, 1):
        try:
            print(f"Test {i}: {create_phone_number(t)}")
        except Exception as e:
            print(f"Test {i} Error: {e}")