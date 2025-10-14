def create_phone_number(numbers):
    if numbers is None or len(numbers) != 10:
        raise ValueError("Input must be 10 integers")
    for n in numbers:
        if n < 0 or n > 9:
            raise ValueError("Digits must be between 0 and 9")
    return "({}{}{}) {}{}{}-{}{}{}{}".format(
        numbers[0], numbers[1], numbers[2],
        numbers[3], numbers[4], numbers[5],
        numbers[6], numbers[7], numbers[8], numbers[9]
    )

if __name__ == "__main__":
    tests = [
        [1,2,3,4,5,6,7,8,9,0],
        [0,0,0,0,0,0,0,0,0,0],
        [9,8,7,6,5,4,3,2,1,0],
        [5,5,5,1,2,3,4,5,6,7],
        [1,2,3,1,2,3,1,2,3,4]
    ]
    for t in tests:
        print(create_phone_number(t))