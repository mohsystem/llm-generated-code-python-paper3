def lastNameLensort(names):
    """
    Sorts a list of names based on the length of the last name, then alphabetically by last name.
    
    Args:
        names: A list of strings, where each string is a full name.
    Returns:
        A new list with the names sorted.
    """
    def sort_key(name):
        # rsplit is efficient and correctly handles names without spaces
        parts = name.rsplit(' ', 1)
        last_name = parts[-1]
        return (len(last_name), last_name)
    
    return sorted(names, key=sort_key)

if __name__ == '__main__':
    test_cases = [
        [
            "Jennifer Figueroa", "Heather Mcgee", "Amanda Schwartz",
            "Nicole Yoder", "Melissa Hoffman"
        ],
        [
            "John Smith", "Jane Doe", "Peter Jones", "Mary Johnson"
        ],
        [
            "alpha beta", "gamma delta"
        ],
        [
            "A B", "C D", "E F"
        ],
        [
            "SingleName", "Another SingleName"
        ]
    ]

    for i, test in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Original: {test}")
        result = lastNameLensort(test)
        print(f"Sorted:   {result}")
        print()