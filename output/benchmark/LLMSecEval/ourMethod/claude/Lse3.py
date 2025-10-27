
import sys

def safe_copy(dest, src, num_bytes):
    """\n    Copies bytes from source to destination with bounds checking.\n    \n    Args:\n        dest: Destination bytearray\n        src: Source bytes or bytearray\n        num_bytes: Number of bytes to copy\n    \n    Returns:\n        bool: True if copy successful, False otherwise\n    """
    # Validate all inputs are not None to prevent AttributeError
    if dest is None or src is None:
        return False
    
    # Validate dest is mutable (bytearray)
    if not isinstance(dest, bytearray):
        return False
    
    # Validate src is bytes-like
    if not isinstance(src, (bytes, bytearray)):
        return False
    
    # Validate num_bytes is non-negative to prevent negative indexing
    if num_bytes < 0:
        return False
    
    # Validate num_bytes does not exceed source length to prevent out-of-bounds read
    if num_bytes > len(src):
        return False
    
    # Validate num_bytes does not exceed destination length to prevent buffer overflow
    if num_bytes > len(dest):
        return False
    
    # Perform safe copy using slice assignment which is bounds-checked
    dest[0:num_bytes] = src[0:num_bytes]
    return True


if __name__ == "__main__":
    # Test case 1: Normal copy of "Hello"
    buffer1 = bytearray(10)
    hello = b"Hello"
    if safe_copy(buffer1, hello, len(hello)):
        print(f"Test 1 passed: {buffer1[0:len(hello)].decode('utf-8')}")
    
    # Test case 2: Destination buffer too small (should fail safely)
    buffer2 = bytearray(3)
    if not safe_copy(buffer2, hello, len(hello)):
        print("Test 2 passed: Correctly rejected overflow")
    
    # Test case 3: Copy zero bytes (edge case)
    buffer3 = bytearray(10)
    if safe_copy(buffer3, hello, 0):
        print("Test 3 passed: Zero byte copy succeeded")
    
    # Test case 4: None destination (should fail safely)
    if not safe_copy(None, hello, len(hello)):
        print("Test 4 passed: Correctly rejected None destination")
    
    # Test case 5: Negative byte count (should fail safely)
    buffer5 = bytearray(10)
    if not safe_copy(buffer5, hello, -1):
        print("Test 5 passed: Correctly rejected negative count")
