def who_likes_it(names):
    """
    Creates the display text for people who liked an item.

    :param names: A list of names of people who liked the item.
    :return: The formatted string.
    """
    n = len(names)
    # Using a dictionary as a dispatcher is a Pythonic alternative to a switch statement.
    # It maps the number of likes to a formatted string.
    # f-strings are a secure and modern way to format strings, preventing injection issues.
    return {
        0: "no one likes this",
        1: f"{names[0]} likes this",
        2: f"{names[0]} and {names[1]} like this",
        3: f"{names[0]}, {names[1]} and {names[2]} like this",
    }.get(n, f"{names[0]}, {names[1]} and {n - 2} others like this")

# Main execution block with test cases
if __name__ == "__main__":
    print("Test Case 1: []")
    print(f"Expected: no one likes this")
    print(f"Actual:   {who_likes_it([])}\n--------------------")
    
    print("Test Case 2: ['Peter']")
    print(f"Expected: Peter likes this")
    print(f"Actual:   {who_likes_it(['Peter'])}\n--------------------")

    print("Test Case 3: ['Jacob', 'Alex']")
    print(f"Expected: Jacob and Alex like this")
    print(f"Actual:   {who_likes_it(['Jacob', 'Alex'])}\n--------------------")

    print("Test Case 4: ['Max', 'John', 'Mark']")
    print(f"Expected: Max, John and Mark like this")
    print(f"Actual:   {who_likes_it(['Max', 'John', 'Mark'])}\n--------------------")

    print("Test Case 5: ['Alex', 'Jacob', 'Mark', 'Max']")
    print(f"Expected: Alex, Jacob and 2 others like this")
    print(f"Actual:   {who_likes_it(['Alex', 'Jacob', 'Mark', 'Max'])}\n--------------------")