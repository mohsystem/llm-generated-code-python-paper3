
def filter_list(lst):
    if lst is None:
        return []
    
    return [item for item in lst if isinstance(item, int) and not isinstance(item, bool)]

def main():
    # Test case 1
    test1 = [1, 2, "a", "b"]
    print(f"Test 1: {filter_list(test1)}")
    
    # Test case 2
    test2 = [1, "a", "b", 0, 15]
    print(f"Test 2: {filter_list(test2)}")
    
    # Test case 3
    test3 = [1, 2, "a", "b", "aasf", "1", "123", 123]
    print(f"Test 3: {filter_list(test3)}")
    
    # Test case 4
    test4 = [5, "test", 10, "string", 20]
    print(f"Test 4: {filter_list(test4)}")
    
    # Test case 5
    test5 = [100, 200, 300]
    print(f"Test 5: {filter_list(test5)}")

if __name__ == "__main__":
    main()
