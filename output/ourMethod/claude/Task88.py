
import tempfile
import secrets
import string
from pathlib import Path
from typing import Optional

RANDOM_STRING_LENGTH: int = 32
CHARS: str = string.ascii_letters + string.digits

def create_random_string(length: int) -> str:
    if length <= 0 or length > 10000:
        raise ValueError("Length must be between 1 and 10000")
    return ''.join(secrets.choice(CHARS) for _ in range(length))

def convert_to_unicode(input_str: str) -> str:
    if input_str is None:
        raise ValueError("Input string cannot be None")
    return ''.join(f'\\u{ord(c):04x}' for c in input_str)

def create_temp_file_with_unicode() -> str:
    random_string: str = create_random_string(RANDOM_STRING_LENGTH)
    unicode_string: str = convert_to_unicode(random_string)
    
    fd, temp_path = tempfile.mkstemp(suffix='.txt', prefix='temp_', text=True)
    
    try:
        with open(fd, 'w', encoding='utf-8') as f:
            f.write(unicode_string)
            f.flush()
    except Exception as e:
        import os
        os.close(fd)
        os.unlink(temp_path)
        raise
    
    return temp_path

def main() -> None:
    try:
        # Test case 1
        path1 = create_temp_file_with_unicode()
        print(f"Test 1 - Temp file created: {path1}")
        
        # Test case 2
        path2 = create_temp_file_with_unicode()
        print(f"Test 2 - Temp file created: {path2}")
        
        # Test case 3
        path3 = create_temp_file_with_unicode()
        print(f"Test 3 - Temp file created: {path3}")
        
        # Test case 4
        path4 = create_temp_file_with_unicode()
        print(f"Test 4 - Temp file created: {path4}")
        
        # Test case 5
        path5 = create_temp_file_with_unicode()
        print(f"Test 5 - Temp file created: {path5}")
        
    except Exception as e:
        print(f"Error creating temp file: {e}")

if __name__ == "__main__":
    main()
