import sys

def demonstrate_double_free_concept(buffer_size, loop_count):
    """
    Demonstrates the double-free concept in Python.
    Python is memory-safe and uses a garbage collector. You cannot explicitly free memory like in C.
    The 'del' keyword unbinds a name. Trying to 'del' the same name twice will raise a NameError.
    This demonstrates the logical error of acting on a resource that has already been dealt with.
    """
    if buffer_size <= 0 or loop_count <= 0:
        print("Invalid size or loop count.")
        return

    try:
        print(f"Allocating buffer of size: {buffer_size}")
        # In Python, a bytearray is a mutable sequence of integers in the range 0 <= x < 256
        buffer = bytearray(buffer_size)
        print("Buffer allocated.")

        for i in range(loop_count):
            print(f"Loop {i + 1}: Deleting buffer reference.")
            # The first 'del' removes the name 'buffer' from the local scope.
            # Subsequent attempts in the loop will fail because the name no longer exists.
            del buffer
        
    except NameError as e:
        print(f"Caught expected error: {e}. This happens on the second attempt to 'del'.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        print(f"Completed demonstration for buffer size {buffer_size}")
        print("------------------------------------")


if __name__ == '__main__':
    # Test Cases
    demonstrate_double_free_concept(1024, 2)
    demonstrate_double_free_concept(256, 3)
    demonstrate_double_free_concept(1, 5)
    demonstrate_double_free_concept(4096, 1) # This one will not error
    demonstrate_double_free_concept(128, 10)