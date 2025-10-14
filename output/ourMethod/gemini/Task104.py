import sys
from typing import Optional

BUFFER_SIZE = 64

def handle_input(user_input: Optional[str]) -> bytearray:
    """
    Safely copies user input string into a fixed-size byte buffer.
    The input string is encoded to UTF-8. If the encoded string is
    too long, it is truncated. The buffer is zero-padded.
    """
    buffer = bytearray(BUFFER_SIZE)

    if not isinstance(user_input, str):
        return buffer  # Return zeroed buffer for non-string or None input

    try:
        input_bytes = user_input.encode('utf-8')
        
        # Determine how many bytes to copy to prevent overflow
        bytes_to_copy = min(len(input_bytes), BUFFER_SIZE)
        
        # Copy the determined number of bytes into the buffer slice
        buffer[:bytes_to_copy] = input_bytes[:bytes_to_copy]
    except Exception as e:
        print(f"An error occurred during encoding: {e}", file=sys.stderr)

    return buffer

def main():
    """
    Main function with 5 test cases.
    """
    test_cases = [
        "This is a short input.",
        "This is a very long input string that is definitely going to be longer than the sixty-four character buffer we have defined, thus causing truncation.",
        "",
        "This input string is exactly 64 characters long to test boundary.",
        None,
    ]

    for i, test_str in enumerate(test_cases):
        print(f"Test Case #{i + 1}")
        print(f"Input: {repr(test_str)}")
        
        result_buffer = handle_input(test_str)
        
        # Decode for printing, stopping at the first null byte
        try:
            first_null = result_buffer.index(0)
            decoded_str = result_buffer[:first_null].decode('utf-8', errors='ignore')
        except ValueError:
            # No null byte found, so the buffer is full
            decoded_str = result_buffer.decode('utf-8', errors='ignore')
            
        print(f"Buffer Content: \"{decoded_str}\"")
        print(f"Buffer Size: {len(result_buffer)}")
        print("--------------------")

if __name__ == "__main__":
    main()