def who_likes_it(names):
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
        return f"{names[0]}, {names[1]} and {n-2} others like this"

if __name__ == '__main__':
    # Test Case 1
    print(who_likes_it([])) # Expected: "no one likes this"
    
    # Test Case 2
    print(who_likes_it(['Peter'])) # Expected: "Peter likes this"
    
    # Test Case 3
    print(who_likes_it(['Jacob', 'Alex'])) # Expected: "Jacob and Alex like this"
    
    # Test Case 4
    print(who_likes_it(['Max', 'John', 'Mark'])) # Expected: "Max, John and Mark like this"
    
    # Test Case 5
    print(who_likes_it(['Alex', 'Jacob', 'Mark', 'Max'])) # Expected: "Alex, Jacob and 2 others like this"