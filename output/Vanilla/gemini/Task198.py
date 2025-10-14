import random

def rand7():
  """
  The given API rand7(), simulated for testing purposes.
  """
  return random.randint(1, 7)

def rand10():
  """
  Generates a uniform random integer in the range [1, 10] using rand7().
  This implementation uses rejection sampling.
  1. Generate a number in a larger range: (rand7() - 1) * 7 + rand7() gives a
     uniform number in [1, 49].
  2. Accept numbers in the range [1, 40] to map to [1, 10].
  3. Reject numbers in the range [41, 49] and retry.
  """
  while True:
    # Generate a number from 1 to 49 uniformly
    result = (rand7() - 1) * 7 + rand7()
    
    # If the number is in the desired range [1, 40], we can use it
    if result <= 40:
      # Map the number from [1, 40] to [1, 10]
      return (result - 1) % 10 + 1
    # Otherwise, reject and try again

if __name__ == "__main__":
    test_cases = [1, 2, 3, 5, 10]
    for n in test_cases:
        result = [rand10() for _ in range(n)]
        print(result)