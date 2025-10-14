
import tempfile
import random
import string
import os

def create_temp_file_with_unicode(string_length):
    # Create a random string
    random_string = generate_random_string(string_length)
    
    # Convert string to Unicode representation
    unicode_string = convert_to_unicode(random_string)
    
    # Create temporary file with UTF-8 encoding
    temp_file = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt')
    
    # Write Unicode string to file
    temp_file.write(unicode_string)
    temp_file.close()
    
    return temp_file.name

def generate_random_string(length):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def convert_to_unicode(input_string):
    unicode_string = ''
    for char in input_string:
        unicode_string += f'\\\\u{ord(char):04x}'
    return unicode_string

if __name__ == '__main__':
    # Test case 1: Create temp file with 10 character string
    print("Test Case 1:")
    path1 = create_temp_file_with_unicode(10)
    print(f"Temp file created at: {path1}")
    with open(path1, 'r', encoding='utf-8') as f:
        print(f"Content: {f.read()}")
    print()
    
    # Test case 2: Create temp file with 20 character string
    print("Test Case 2:")
    path2 = create_temp_file_with_unicode(20)
    print(f"Temp file created at: {path2}")
    with open(path2, 'r', encoding='utf-8') as f:
        print(f"Content: {f.read()}")
    print()
    
    # Test case 3: Create temp file with 5 character string
    print("Test Case 3:")
    path3 = create_temp_file_with_unicode(5)
    print(f"Temp file created at: {path3}")
    with open(path3, 'r', encoding='utf-8') as f:
        print(f"Content: {f.read()}")
    print()
    
    # Test case 4: Create temp file with 15 character string
    print("Test Case 4:")
    path4 = create_temp_file_with_unicode(15)
    print(f"Temp file created at: {path4}")
    with open(path4, 'r', encoding='utf-8') as f:
        print(f"Content: {f.read()}")
    print()
    
    # Test case 5: Create temp file with 25 character string
    print("Test Case 5:")
    path5 = create_temp_file_with_unicode(25)
    print(f"Temp file created at: {path5}")
    with open(path5, 'r', encoding='utf-8') as f:
        print(f"Content: {f.read()}")
    print()
