import collections.abc

def last_name_lensort(names):
    """
    Sorts a list of names based on the length of the last name,
    then alphabetically by last name.
    """
    if not isinstance(names, collections.abc.Sequence):
        # Handle non-list inputs gracefully for security
        return []

    def get_sort_key(full_name):
        """
        Helper function to generate a sort key (tuple) for a given name.
        The key is (length_of_last_name, last_name).
        """
        # Ensure input is a string and handle empty/whitespace-only strings
        if not isinstance(full_name, str) or not full_name.strip():
            return (0, "")
        
        # The last name is the last word after splitting by whitespace
        parts = full_name.strip().split()
        last_name = parts[-1]
        return (len(last_name), last_name)

    # Use Python's built-in sorted function with a custom key
    return sorted(names, key=get_sort_key)

def main():
    """ Main function with test cases """
    test_cases = [
        # Test Case 1: Example from prompt
        ["Jennifer Figueroa", "Heather Mcgee", "Amanda Schwartz", "Nicole Yoder", "Melissa Hoffman"],
        # Test Case 2: Last names with same length
        ["Steven King", "John Smith", "Jane Doe"],
        # Test Case 3: Names without spaces
        ["Beyonce", "Adele", "Cher"],
        # Test Case 4: Mixed names (with and without spaces)
        ["David Copperfield", "David Blaine", "Penn"],
        # Test Case 5: Edge cases
        ["", " ", "Single", "Peter Pan", None]
    ]

    for i, test in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Input: {test}")
        print(f"Output: {last_name_lensort(test)}")
        print()

if __name__ == "__main__":
    main()