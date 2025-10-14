
import os
import sys
from typing import List, Tuple

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

def read_and_sort_key_value_file(filename: str) -> List[Tuple[str, str]]:
    """\n    Reads a file containing key-value pairs and returns them sorted by key.\n    \n    Args:\n        filename: Path to the file to read\n        \n    Returns:\n        List of tuples containing (key, value) pairs sorted by key\n    """
    records = []
    
    try:
        # Validate file path
        normalized_path = os.path.normpath(filename)
        
        if not os.path.exists(normalized_path):
            print(f"File not found: {filename}", file=sys.stderr)
            return records
        
        # Check file size
        if os.path.getsize(normalized_path) > MAX_FILE_SIZE:
            print("File size exceeds maximum allowed size", file=sys.stderr)
            return records
        
        # Read and parse file
        with open(normalized_path, 'r', encoding='utf-8') as file:
            line_number = 0
            for line in file:
                line_number += 1
                line = line.strip()
                
                # Skip empty lines
                if not line:
                    continue
                
                # Parse key-value pair (format: key=value or key:value)
                if '=' in line:
                    parts = line.split('=', 1)
                elif ':' in line:
                    parts = line.split(':', 1)
                else:
                    print(f"Invalid format at line {line_number}: {line}", file=sys.stderr)
                    continue
                
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    records.append((key, value))
                else:
                    print(f"Invalid format at line {line_number}: {line}", file=sys.stderr)
        
        # Sort by key
        records.sort(key=lambda x: x[0])
        
    except IOError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
    
    return records


def main():
    """Main function with test cases"""
    test_file = "test_keyvalue.txt"
    
    try:
        # Test case 1: Basic key-value pairs
        with open(test_file, 'w') as f:
            f.write("name=John\\n")
            f.write("age=30\\n")
            f.write("city=NewYork\\n")
            f.write("country=USA\\n")
            f.write("email=john@example.com\\n")
        
        print("Test Case 1: Basic key-value pairs")
        result1 = read_and_sort_key_value_file(test_file)
        for key, value in result1:
            print(f"{key} = {value}")
        
        # Test case 2: Colon separator
        with open(test_file, 'w') as f:
            f.write("zebra:animal\\n")
            f.write("apple:fruit\\n")
            f.write("carrot:vegetable\\n")
        
        print("\\nTest Case 2: Colon separator")
        result2 = read_and_sort_key_value_file(test_file)
        for key, value in result2:
            print(f"{key} : {value}")
        
        # Test case 3: Mixed with empty lines
        with open(test_file, 'w') as f:
            f.write("dog=animal\\n")
            f.write("\\n")
            f.write("banana=fruit\\n")
            f.write("apple=fruit\\n")
        
        print("\\nTest Case 3: With empty lines")
        result3 = read_and_sort_key_value_file(test_file)
        for key, value in result3:
            print(f"{key} = {value}")
        
        # Test case 4: Non-existent file
        print("\\nTest Case 4: Non-existent file")
        result4 = read_and_sort_key_value_file("nonexistent.txt")
        print(f"Records found: {len(result4)}")
        
        # Test case 5: Invalid format
        with open(test_file, 'w') as f:
            f.write("validkey=validvalue\\n")
            f.write("invalidline\\n")
            f.write("anotherkey=anothervalue\\n")
        
        print("\\nTest Case 5: Invalid format handling")
        result5 = read_and_sort_key_value_file(test_file)
        for key, value in result5:
            print(f"{key} = {value}")
        
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
            
    except Exception as e:
        print(f"Error in test setup: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
