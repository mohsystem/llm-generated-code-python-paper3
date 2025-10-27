def copy_bytes(dest: bytearray, src: bytes, num_bytes: int) -> bool:
    """
    Securely copies a number of bytes from a source to a destination.

    :param dest: The destination bytearray (must be mutable).
    :param src: The source bytes or bytearray.
    :param num_bytes: The number of bytes to copy.
    :return: True if the copy was successful, False otherwise.
    """
    # 1. Check for None objects
    if dest is None or src is None:
        print("Error: Destination or source is None.", flush=True)
        return False

    # 2. Check for invalid num_bytes
    if num_bytes < 0:
        print("Error: Number of bytes to copy cannot be negative.", flush=True)
        return False
        
    # A zero-byte copy is a no-op and is considered a success.
    if num_bytes == 0:
        return True

    # 3. Check for potential buffer overflow on destination
    if num_bytes > len(dest):
        print(f"Error: Buffer overflow detected. Cannot copy {num_bytes} bytes into a destination of size {len(dest)}", flush=True)
        return False
    
    # 4. Check for potential out-of-bounds read on source
    if num_bytes > len(src):
        print(f"Error: Source read out of bounds. Cannot copy {num_bytes} bytes from a source of size {len(src)}", flush=True)
        return False
    
    # Perform the copy using slicing, which is safe in Python.
    dest[:num_bytes] = src[:num_bytes]
    return True

def main():
    print("--- Python Test Cases ---")

    source_string = "Hello"
    source_bytes = source_string.encode('utf-8') + b'\0'
    bytes_to_copy = len(source_bytes) # 6 bytes for "Hello\0"

    # Test Case 1: Normal copy
    print("\n--- Test Case 1: Normal copy ---")
    dest1 = bytearray(10)
    if copy_bytes(dest1, source_bytes, bytes_to_copy):
        # -1 to exclude null terminator for printing
        print(f"Success! Copied string: \"{dest1[:bytes_to_copy-1].decode('utf-8')}\"")
    else:
        print("Failed!")

    # Test Case 2: Exact size copy
    print("\n--- Test Case 2: Exact size copy ---")
    dest2 = bytearray(bytes_to_copy)
    if copy_bytes(dest2, source_bytes, bytes_to_copy):
        print(f"Success! Copied string: \"{dest2[:bytes_to_copy-1].decode('utf-8')}\"")
    else:
        print("Failed!")

    # Test Case 3: Buffer overflow attempt
    print("\n--- Test Case 3: Buffer overflow attempt ---")
    dest3 = bytearray(4)
    if copy_bytes(dest3, source_bytes, bytes_to_copy):
        print("Success! (This should not happen)")
    else:
        print("Failed as expected.")

    # Test Case 4: None object
    print("\n--- Test Case 4: None object ---")
    dest4 = None
    if copy_bytes(dest4, source_bytes, bytes_to_copy):
        print("Success! (This should not happen)")
    else:
        print("Failed as expected.")
        
    # Test Case 5: Zero bytes copy
    print("\n--- Test Case 5: Zero bytes copy ---")
    dest5 = bytearray(10)
    if copy_bytes(dest5, source_bytes, 0):
        print("Success! Copied 0 bytes.")
    else:
        print("Failed! (This should not happen)")

if __name__ == "__main__":
    main()