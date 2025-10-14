from typing import List

def who_likes_it(names: List[str]) -> str:
    """
    Creates a display text for "likes" based on a list of names.
    :param names: A list of strings representing the names of people who liked an item.
    :return: A formatted string.
    """
    # Rule #1: Input validation. The logic inherently handles different lengths.
    n = len(names)
    if n == 0:
        return "no one likes this"
    elif n == 1:
        # Using safe f-string formatting
        return f"{names[0]} likes this"
    elif n == 2:
        return f"{names[0]} and {names[1]} like this"
    elif n == 3:
        return f"{names[0]}, {names[1]} and {names[2]} like this"
    else:
        return f"{names[0]}, {names[1]} and {n - 2} others like this"

if __name__ == '__main__':
    # Test case 1
    test1 = []
    print(f"Input: {test1} -> Output: \"{who_likes_it(test1)}\"")

    # Test case 2
    test2 = ["Peter"]
    print(f"Input: {test2} -> Output: \"{who_likes_it(test2)}\"")

    # Test case 3
    test3 = ["Jacob", "Alex"]
    print(f"Input: {test3} -> Output: \"{who_likes_it(test3)}\"")

    # Test case 4
    test4 = ["Max", "John", "Mark"]
    print(f"Input: {test4} -> Output: \"{who_likes_it(test4)}\"")

    # Test case 5
    test5 = ["Alex", "Jacob", "Mark", "Max"]
    print(f"Input: {test5} -> Output: \"{who_likes_it(test5)}\"")