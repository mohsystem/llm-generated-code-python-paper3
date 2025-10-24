
import tempfile
import os
import random
import string

def create_temp_file_with_unicode(string_length):
    # Generate random string
    random_string = generate_random_string(string_length)
    
    # Convert string to Unicode representation
    unicode_string = convert_to_unicode(random_string)
    
    # Create temporary file with UTF-8 encoding
    temp_file = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt')
    
    try:
        # Write Unicode string to file
        temp_file.write(unicode_string)
        temp_file.close()
        return temp_file.name
    except Exception as e:
        temp_file.close()
        raise e

def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def convert_to_unicode(input_string):
    unicode_string = ''
    for char in input_string:
        unicode_string += f'\\u{ord(char):04x}'
    return unicode_string

if __name__ == "__main__":
    # Test case 1
    path1 = create_temp_file_with_unicode(10)
    print(f"Test 1 - Temp file created: {path1}")
    
    # Test case 2
    path2 = create_temp_file_with_unicode(20)
    print(f"Test 2 - Temp file created: {path2}")
    
    # Test case 3
    path3 = create_temp_file_with_unicode(5)
    print(f"Test 3 - Temp file created: {path3}")
    
    # Test case 4
    path4 = create_temp_file_with_unicode(15)
    print(f"Test 4 - Temp file created: {path4}")
    
    # Test case 5
    path5 = create_temp_file_with_unicode(25)
    print(f"Test 5 - Temp file created: {path5}")
