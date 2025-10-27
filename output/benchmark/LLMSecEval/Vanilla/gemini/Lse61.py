# Python uses automatic garbage collection, similar to Java.
# The 'del' keyword decrements an object's reference count. When the count
# reaches zero, the object is eligible for collection.
# After 'del' is used on a variable, the variable name is removed.
# Trying to 'del' the same variable name again will raise a NameError.
# This code demonstrates how Python's memory management prevents
# double-free vulnerabilities by raising an error instead of causing
# undefined behavior.

def free_buffer_in_loop(buffer_size):
    if buffer_size <= 0:
        print("Buffer size must be positive.")
        return

    print(f"Allocating buffer of size: {buffer_size}")
    buffer = bytearray(buffer_size)

    print("Attempting to 'free' the buffer in a loop (using 'del')...")
    for i in range(2):
        try:
            # The first time this runs, it deletes the reference.
            del buffer
            print(f"Loop {i + 1}: 'del' successful. The name 'buffer' is now unbound.")
        except NameError:
            # The second time, 'buffer' no longer exists, raising a NameError.
            print(f"Loop {i + 1}: Cannot 'del' again. NameError: name 'buffer' is not defined.")
    
    print("Operation completed.\n")


def main():
    print("--- Test Case 1 ---")
    free_buffer_in_loop(1024)

    print("--- Test Case 2 ---")
    free_buffer_in_loop(256)

    print("--- Test Case 3 ---")
    free_buffer_in_loop(1)

    print("--- Test Case 4 ---")
    free_buffer_in_loop(0)
    
    print("--- Test Case 5 ---")
    free_buffer_in_loop(4096)

if __name__ == "__main__":
    main()