BUFFER_SIZE = 100

def handle_input(input_str):
    """
    Safely handles user input into a fixed-size buffer
    :param input_str: The input string to be stored
    :return: The safely stored string (truncated if necessary)
    """
    if input_str is None:
        return ""

    # Ensure input doesn't exceed buffer size
    if len(input_str) > BUFFER_SIZE:
        return input_str[:BUFFER_SIZE]

    return input_str


def store_in_buffer(input_str):
    """
    Stores input into a character buffer safely
    :param input_str: The input string
    :return: Byte array buffer with safe content
    """
    buffer = bytearray(BUFFER_SIZE)

    if input_str is None or len(input_str) == 0:
        return buffer

    length = min(len(input_str), BUFFER_SIZE)
    input_bytes = input_str.encode('utf-8')[:length]
    buffer[:len(input_bytes)] = input_bytes

    return buffer


def main():
    print("Testing Fixed-Size Buffer Input Handler\n")

    # Test case 1: Normal input
    test1 = "Hello, World!"
    print("Test 1 - Normal input:")
    print(f"Input: {test1}")
    print(f"Output: {handle_input(test1)}")
    print(f"Buffer: {store_in_buffer(test1).decode('utf-8', errors='ignore').rstrip(chr(0))}")
    print()

    # Test case 2: Empty input
    test2 = ""
    print("Test 2 - Empty input:")
    print('Input: ""')
    print(f"Output: {handle_input(test2)}")
    print()

    # Test case 3: Input exceeding buffer size
    test3 = "A" * 150
    print("Test 3 - Input exceeding buffer size (150 chars):")
    print(f"Input length: {len(test3)}")
    result3 = handle_input(test3)
    print(f"Output length: {len(result3)}")
    print(f"Truncated: {len(test3) > len(result3)}")
    print()

    # Test case 4: Input at buffer boundary
    test4 = "B" * 100
    print("Test 4 - Input at buffer boundary (100 chars):")
    print(f"Input length: {len(test4)}")
    result4 = handle_input(test4)
    print(f"Output length: {len(result4)}")
    print()

    # Test case 5: Null input
    test5 = None
    print("Test 5 - Null input:")
    print("Input: None")
    print(f'Output: "{handle_input(test5)}"')


if __name__ == "__main__":
    main()
