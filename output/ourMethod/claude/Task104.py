
import sys
from typing import Optional, Tuple

BUFFER_SIZE = 256

def handle_user_input(input_str: Optional[str], max_buffer_size: int) -> Tuple[bool, str, Optional[bytes]]:
    """\n    Handles user input into a fixed-size buffer with proper validation.\n    \n    Returns: (success, message, data)\n    """
    if input_str is None:
        return (False, "Input cannot be None", None)
    
    if max_buffer_size <= 0 or max_buffer_size > 1048576:
        return (False, "Invalid buffer size", None)
    
    input_bytes = input_str.encode('utf-8')
    
    if len(input_bytes) > max_buffer_size:
        return (False, 
                f"Input exceeds buffer size limit ({len(input_bytes)} > {max_buffer_size})", 
                None)
    
    buffer = bytearray(max_buffer_size)
    
    buffer[:len(input_bytes)] = input_bytes
    
    result = bytes(buffer[:len(input_bytes)])
    return (True, "Input handled successfully", result)


def main() -> None:
    print("=== Test Case 1: Valid short input ===")
    success1, message1, data1 = handle_user_input("Hello World", BUFFER_SIZE)
    print(f"Success: {success1}")
    print(f"Message: {message1}")
    if data1 is not None:
        print(f"Data: {data1.decode('utf-8')}")
    
    print("\\n=== Test Case 2: Empty input ===")
    success2, message2, data2 = handle_user_input("", BUFFER_SIZE)
    print(f"Success: {success2}")
    print(f"Message: {message2}")
    
    print("\\n=== Test Case 3: Input at buffer limit ===")
    max_input = "A" * BUFFER_SIZE
    success3, message3, data3 = handle_user_input(max_input, BUFFER_SIZE)
    print(f"Success: {success3}")
    print(f"Message: {message3}")
    if data3 is not None:
        print(f"Data length: {len(data3)}")
    
    print("\\n=== Test Case 4: Input exceeding buffer size ===")
    oversize_input = "B" * (BUFFER_SIZE + 10)
    success4, message4, data4 = handle_user_input(oversize_input, BUFFER_SIZE)
    print(f"Success: {success4}")
    print(f"Message: {message4}")
    
    print("\\n=== Test Case 5: None input ===")
    success5, message5, data5 = handle_user_input(None, BUFFER_SIZE)
    print(f"Success: {success5}")
    print(f"Message: {message5}")


if __name__ == "__main__":
    main()
