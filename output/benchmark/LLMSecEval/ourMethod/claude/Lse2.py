
def safe_copy(dest, src, num_bytes):
    """\n    Safely copies a specified number of bytes from source to destination.\n    \n    Args:\n        dest: Destination bytearray\n        src: Source bytes or bytearray\n        num_bytes: Number of bytes to copy\n    \n    Returns:\n        Number of bytes actually copied, -1 on error\n    """
    # Input validation: check for None pointers
    if dest is None or src is None:
        return -1
    
    # Input validation: check type
    if not isinstance(dest, bytearray):
        return -1
    
    if not isinstance(src, (bytes, bytearray)):
        return -1
    
    # Input validation: check for negative size
    if num_bytes < 0:
        return -1
    
    # Bounds checking: ensure num_bytes doesn't exceed source length\n    if num_bytes > len(src):\n        return -1\n    \n    # Bounds checking: ensure num_bytes doesn't exceed destination length
    if num_bytes > len(dest):
        return -1
    
    # Safe copy using slicing with bounds already validated
    dest[:num_bytes] = src[:num_bytes]
    
    return num_bytes


if __name__ == "__main__":
    # Test case 1: Normal copy
    dest1 = bytearray(20)
    src1 = b"Hello"
    result1 = safe_copy(dest1, src1, len(src1))
    print(f"Test 1: {'PASS' if result1 == len(src1) else 'FAIL'}")
    
    # Test case 2: Copy with buffer larger than source
    dest2 = bytearray(100)
    src2 = b"Test"
    result2 = safe_copy(dest2, src2, len(src2))
    print(f"Test 2: {'PASS' if result2 == len(src2) else 'FAIL'}")
    
    # Test case 3: Attempt to copy more bytes than source has (should fail)
    dest3 = bytearray(20)
    src3 = b"Hi"
    result3 = safe_copy(dest3, src3, 10)
    print(f"Test 3: {'PASS' if result3 == -1 else 'FAIL'}")
    
    # Test case 4: Attempt to copy more bytes than destination can hold (should fail)
    dest4 = bytearray(3)
    src4 = b"Hello World"
    result4 = safe_copy(dest4, src4, len(src4))
    print(f"Test 4: {'PASS' if result4 == -1 else 'FAIL'}")
    
    # Test case 5: None pointer check
    dest5 = bytearray(10)
    result5 = safe_copy(dest5, None, 5)
    print(f"Test 5: {'PASS' if result5 == -1 else 'FAIL'}")
