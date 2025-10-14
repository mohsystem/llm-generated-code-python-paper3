
import json

def parse_and_get_root(json_string):
    if not json_string or not json_string.strip():
        return None
    
    try:
        root_element = json.loads(json_string)
        return root_element
    except json.JSONDecodeError as e:
        print(f"Invalid JSON syntax: {e}")
        return None

def main():
    # Test case 1: Simple JSON object
    test1 = '{"name": "John", "age": 30}'
    print(f"Test 1 Root: {parse_and_get_root(test1)}")
    
    # Test case 2: JSON array
    test2 = '[1, 2, 3, 4, 5]'
    print(f"Test 2 Root: {parse_and_get_root(test2)}")
    
    # Test case 3: Nested JSON object
    test3 = '{"user": {"name": "Alice", "address": {"city": "NYC"}}}'
    print(f"Test 3 Root: {parse_and_get_root(test3)}")
    
    # Test case 4: Empty JSON object
    test4 = '{}'
    print(f"Test 4 Root: {parse_and_get_root(test4)}")
    
    # Test case 5: Invalid JSON (should handle gracefully)
    test5 = '{invalid json}'
    print(f"Test 5 Root: {parse_and_get_root(test5)}")

if __name__ == "__main__":
    main()
