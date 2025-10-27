
# WARNING: This code contains a critical security vulnerability (double-free)
# For educational purposes only - DO NOT USE IN PRODUCTION

import ctypes
def demonstrate_vulnerability(buffer_size, free_count):
    # Note: Python also has automatic garbage collection
    # We can demonstrate the concept using ctypes for manual memory management

    # Allocate memory using ctypes
    buffer = ctypes.create_string_buffer(buffer_size)
    buffer_address = ctypes.addressof(buffer)

    print(f"Buffer allocated with size: {buffer_size} at address: {hex(buffer_address)}")

    # Python doesn't have explicit free() like C
    # Setting to None and forcing deletion
    for i in range(free_count):
        del buffer
        print(f"Buffer deleted, iteration: {i + 1}")
        if i == 0:
            # After first deletion, buffer doesn't exist
            # Further deletions would cause NameError
            print("Note: Further deletions would cause NameError in Python")
            break

    print("Note: Python uses garbage collection, so double-free vulnerabilities don't exist as in C/C++")

if __name__ == "__main__":
    print("Test Case 1:")
    demonstrate_vulnerability(1024, 3)
    
    print("\\nTest Case 2:")
    demonstrate_vulnerability(2048, 5)
    
    print("\\nTest Case 3:")
    demonstrate_vulnerability(512, 2)
    
    print("\\nTest Case 4:")
    demonstrate_vulnerability(4096, 1)
    
    print("\\nTest Case 5:")
    demonstrate_vulnerability(256, 10)
