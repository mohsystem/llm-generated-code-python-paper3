
import secrets

def generate_random_number():
    # Generate a random number between 1001 and 100000
    random_number = secrets.randbelow(99000) + 1001
    return random_number

def print_random_number(number):
    if number > 1000:
        print(f"Generated random number: {number}")
    else:
        print("Error: Number must be larger than 1000")

if __name__ == "__main__":
    # Test cases
    for i in range(5):
        random_num = generate_random_number()
        print_random_number(random_num)
