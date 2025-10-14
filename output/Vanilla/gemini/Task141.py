def reverse_string(s):
  """
  Reverses a given string.
  :param s: The string to be reversed.
  :return: The reversed string.
  """
  return s[::-1]

def main():
  test_cases = [
    "hello",
    "world",
    "Python",
    "12345",
    ""
  ]

  print("Python Test Cases:")
  for test in test_cases:
    reversed_str = reverse_string(test)
    print(f"Original: \"{test}\", Reversed: \"{reversed_str}\"")

if __name__ == "__main__":
  main()