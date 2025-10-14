def who_likes_it(names):
    """
    Creates a display text for who likes an item based on a list of names.
    
    Args:
        names: A list of strings containing the names of people who like the item.
    
    Returns:
        A formatted string.
    """
    n = len(names)
    if n == 0:
        return "no one likes this"
    elif n == 1:
        return f"{names[0]} likes this"
    elif n == 2:
        return f"{names[0]} and {names[1]} like this"
    elif n == 3:
        return f"{names[0]}, {names[1]} and {names[2]} like this"
    else:
        return f"{names[0]}, {names[1]} and {n - 2} others like this"

if __name__ == '__main__':
    # Test Case 1: 0 names
    print(who_likes_it([]))
    
    # Test Case 2: 1 name
    print(who_likes_it(["Peter"]))
    
    # Test Case 3: 2 names
    print(who_likes_it(["Jacob", "Alex"]))
    
    # Test Case 4: 3 names
    print(who_likes_it(["Max", "John", "Mark"]))
    
    # Test Case 5: 4 or more names
    print(who_likes_it(["Alex", "Jacob", "Mark", "Max"]))