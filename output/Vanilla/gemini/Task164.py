def lastNameLensort(names):
  """
  Sorts a list of names based on the length of the last name, then alphabetically by last name.
  :param names: A list of strings, where each string is a name in "First Last" format.
  :return: The sorted list of names.
  """
  return sorted(names, key=lambda name: (len(name.split()[-1]), name.split()[-1]))

if __name__ == '__main__':
    test_cases = [
        ["Jennifer Figueroa", "Heather Mcgee", "Amanda Schwartz", "Nicole Yoder", "Melissa Hoffman"],
        ["A B", "C D", "E F"],
        ["Morty Smith", "Rick Sanchez", "Jerry Smith"],
        ["Peter Parker", "Clark Kent", "Bruce Wayne"],
        ["Leo Tolstoy", "Jane Austen", "Charles Dickens"]
    ]

    for i, test in enumerate(test_cases):
        print(f"Test Case {i + 1}:")
        print(f"Input: {test}")
        result = lastNameLensort(test)
        print(f"Output: {result}")
        print()