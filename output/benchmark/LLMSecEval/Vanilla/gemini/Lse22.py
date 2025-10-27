import random
import sys

def generate_random_number():
  """
  Generates a random integer greater than 1000.
  :return: An integer > 1000.
  """
  # Generate a random integer from 1001 up to a large number.
  # Using 2**31 - 1 as a practical large upper bound.
  return random.randint(1001, 2**31 - 1)

if __name__ == "__main__":
  print("Generating 5 random numbers greater than 1000:")
  for _ in range(5):
    print(generate_random_number())