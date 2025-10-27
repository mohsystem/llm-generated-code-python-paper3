
def img(request_args):
    try:
        file = request_args.get('file')
        if not file:
            return None
        
        with open(file, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"Error: {e}")
        return None


if __name__ == "__main__":
    # Test case 1: Valid image file
    test1 = {'file': 'test1.jpg'}
    result1 = img(test1)
    print(f"Test 1 - File: test1.jpg, Result: {'Success (' + str(len(result1)) + ' bytes)' if result1 else 'Failed'}")
    
    # Test case 2: Valid text file
    test2 = {'file': 'test2.txt'}
    result2 = img(test2)
    print(f"Test 2 - File: test2.txt, Result: {'Success (' + str(len(result2)) + ' bytes)' if result2 else 'Failed'}")
    
    # Test case 3: Empty file parameter
    test3 = {'file': ''}
    result3 = img(test3)
    print(f"Test 3 - Empty file, Result: {'Success' if result3 else 'Failed (Expected)'}")
    
    # Test case 4: Null file parameter
    test4 = {}
    result4 = img(test4)
    print(f"Test 4 - Null file, Result: {'Success' if result4 else 'Failed (Expected)'}")
    
    # Test case 5: Non-existent file
    test5 = {'file': 'nonexistent.jpg'}
    result5 = img(test5)
    print(f"Test 5 - Non-existent file, Result: {'Success' if result5 else 'Failed (Expected)'}")
