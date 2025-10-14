import typing

def last_name_lensort(names: typing.List[str]) -> typing.List[str]:
    """
    Sorts a list of names based on the length of the last name, 
    then alphabetically by last name.
    """
    if not names:
        return []

    def get_sort_key(full_name: str) -> typing.Tuple[int, str]:
        """
        Returns a tuple (last_name_length, last_name) for sorting.
        Handles names with no spaces correctly.
        """
        parts = full_name.rsplit(' ', 1)
        last_name = parts[-1]
        return (len(last_name), last_name)

    return sorted(names, key=get_sort_key)

if __name__ == '__main__':
    # Test Case 1
    names1 = [
        "Jennifer Figueroa", "Heather Mcgee", "Amanda Schwartz", "Nicole Yoder", "Melissa Hoffman"
    ]
    print("Test Case 1:")
    print(f"Input: {names1}")
    print(f"Output: {last_name_lensort(names1)}")
    print()

    # Test Case 2: Same last name length
    names2 = ["John Smith", "Jane Doe", "Peter Jones"]
    print("Test Case 2:")
    print(f"Input: {names2}")
    print(f"Output: {last_name_lensort(names2)}")
    print()

    # Test Case 3: Empty array
    names3 = []
    print("Test Case 3:")
    print(f"Input: {names3}")
    print(f"Output: {last_name_lensort(names3)}")
    print()

    # Test Case 4: Single-word names
    names4 = ["Cher", "Madonna", "Prince"]
    print("Test Case 4:")
    print(f"Input: {names4}")
    print(f"Output: {last_name_lensort(names4)}")
    print()

    # Test Case 5: Names with same last names
    names5 = ["David Lee", "Bruce Lee", "Sara Lee"]
    print("Test Case 5:")
    print(f"Input: {names5}")
    print(f"Output: {last_name_lensort(names5)}")
    print()