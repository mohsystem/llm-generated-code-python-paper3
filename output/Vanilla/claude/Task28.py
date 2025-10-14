
def who_likes_it(names):
    if not names or len(names) == 0:
        return "no one likes this"
    elif len(names) == 1:
        return f"{names[0]} likes this"
    elif len(names) == 2:
        return f"{names[0]} and {names[1]} like this"
    elif len(names) == 3:
        return f"{names[0]}, {names[1]} and {names[2]} like this"
    else:
        others = len(names) - 2
        return f"{names[0]}, {names[1]} and {others} others like this"

if __name__ == "__main__":
    # Test case 1
    print(who_likes_it([]))
    
    # Test case 2
    print(who_likes_it(["Peter"]))
    
    # Test case 3
    print(who_likes_it(["Jacob", "Alex"]))
    
    # Test case 4
    print(who_likes_it(["Max", "John", "Mark"]))
    
    # Test case 5
    print(who_likes_it(["Alex", "Jacob", "Mark", "Max"]))
