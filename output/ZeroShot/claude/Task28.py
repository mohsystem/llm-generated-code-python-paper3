
def who_likes_it(names):
    if not names or len(names) == 0:
        return "no one likes this"
    
    if len(names) == 1:
        return f"{names[0]} likes this"
    elif len(names) == 2:
        return f"{names[0]} and {names[1]} like this"
    elif len(names) == 3:
        return f"{names[0]}, {names[1]} and {names[2]} like this"
    else:
        return f"{names[0]}, {names[1]} and {len(names) - 2} others like this"


if __name__ == "__main__":
    # Test case 1
    test1 = []
    print(who_likes_it(test1))
    
    # Test case 2
    test2 = ["Peter"]
    print(who_likes_it(test2))
    
    # Test case 3
    test3 = ["Jacob", "Alex"]
    print(who_likes_it(test3))
    
    # Test case 4
    test4 = ["Max", "John", "Mark"]
    print(who_likes_it(test4))
    
    # Test case 5
    test5 = ["Alex", "Jacob", "Mark", "Max"]
    print(who_likes_it(test5))
