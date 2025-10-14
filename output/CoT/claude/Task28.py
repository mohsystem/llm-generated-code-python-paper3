
def who_likes_it(names):
    if names is None:
        return "no one likes this"
    
    length = len(names)
    
    if length == 0:
        return "no one likes this"
    elif length == 1:
        return f"{names[0]} likes this"
    elif length == 2:
        return f"{names[0]} and {names[1]} like this"
    elif length == 3:
        return f"{names[0]}, {names[1]} and {names[2]} like this"
    else:
        return f"{names[0]}, {names[1]} and {length - 2} others like this"

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
