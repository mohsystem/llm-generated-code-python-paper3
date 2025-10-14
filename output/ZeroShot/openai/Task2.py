class Task2:
    @staticmethod
    def create_phone_number(numbers):
        if numbers is None:
            raise ValueError("Input array cannot be None.")
        if len(numbers) != 10:
            raise ValueError("Input array must contain exactly 10 integers.")
        for n in numbers:
            if not isinstance(n, int) or n < 0 or n > 9:
                raise ValueError("All numbers must be integers in the range 0 to 9.")
        return f"({numbers[0]}{numbers[1]}{numbers[2]}) {numbers[3]}{numbers[4]}{numbers[5]}-{numbers[6]}{numbers[7]}{numbers[8]}{numbers[9]}"

if __name__ == "__main__":
    tests = [
        [1,2,3,4,5,6,7,8,9,0],
        [0,0,0,0,0,0,0,0,0,0],
        [9,8,7,6,5,4,3,2,1,0],
        [1,1,1,1,1,1,1,1,1,1],
        [1,2,3,4,-5,6,7,8,9,0]  # invalid
    ]
    for i, t in enumerate(tests, 1):
        try:
            print(f"Test {i} ({t}): {Task2.create_phone_number(t)}")
        except Exception as e:
            print(f"Test {i} ({t}): ERROR - {e}")