import sys

def trim_trailing(s):
  return s.rstrip()

def main():
  if len(sys.argv) > 1:
    print(trim_trailing(sys.argv[1]))
  else:
    print("--- Running Test Cases ---")
    test_cases = [
        "Hello World   ",
        "  leading and trailing  ",
        "no_whitespace",
        "   \t\n",
        "Trailing tab\t"
    ]
    for test in test_cases:
      print(f"Original: [{test}]")
      print(f"Trimmed:  [{trim_trailing(test)}]")
      print()

if __name__ == "__main__":
  main()