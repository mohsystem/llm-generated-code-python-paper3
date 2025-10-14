def is_valid_walk(walk):
    return len(walk) == 10 and walk.count('n') == walk.count('s') and walk.count('e') == walk.count('w')

if __name__ == "__main__":
    walk1 = ['n', 's', 'n', 's', 'n', 's', 'n', 's', 'n', 's']
    print("Test 1:", is_valid_walk(walk1))

    walk2 = ['w', 'e', 'w', 'e', 'w', 'e', 'w', 'e', 'w', 'e', 'w', 'e']
    print("Test 2:", is_valid_walk(walk2))

    walk3 = ['w']
    print("Test 3:", is_valid_walk(walk3))

    walk4 = ['n', 'n', 'n', 's', 'n', 's', 'n', 's', 'n', 's']
    print("Test 4:", is_valid_walk(walk4))
    
    walk5 = ['e', 'w', 'e', 'w', 'n', 's', 'n', 's', 'e', 'w']
    print("Test 5:", is_valid_walk(walk5))