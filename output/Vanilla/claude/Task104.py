
BUFFER_SIZE = 100

def handle_user_input(input_str):
    if input_str is None:
        return ""
    
    # Truncate input if it exceeds buffer size
    if len(input_str) > BUFFER_SIZE:
        return input_str[:BUFFER_SIZE]
    
    return input_str

def handle_user_input_to_list(input_str):
    buffer = ['\\0'] * BUFFER_SIZE
    
    if input_str is None:
        return buffer
    
    length = min(len(input_str), BUFFER_SIZE)
    for i in range(length):
        buffer[i] = input_str[i]
    
    return buffer

if __name__ == "__main__":
    print("Test Case 1: Normal input")
    input1 = "Hello, World!"
    result1 = handle_user_input(input1)
    print(f"Input: {input1}")
    print(f"Output: {result1}")
    print(f"Length: {len(result1)}")
    print()
    
    print("Test Case 2: Empty input")
    input2 = ""
    result2 = handle_user_input(input2)
    print("Input: (empty)")
    print(f"Output: {result2}")
    print(f"Length: {len(result2)}")
    print()
    
    print("Test Case 3: Input exceeding buffer size")
    input3 = "A" * 150
    result3 = handle_user_input(input3)
    print(f"Input length: {len(input3)}")
    print(f"Output length: {len(result3)}")
    print(f"Truncated: {len(result3) == BUFFER_SIZE}")
    print()
    
    print("Test Case 4: Input at buffer boundary")
    input4 = "B" * 100
    result4 = handle_user_input(input4)
    print(f"Input length: {len(input4)}")
    print(f"Output length: {len(result4)}")
    print()
    
    print("Test Case 5: Null input")
    input5 = None
    result5 = handle_user_input(input5)
    print("Input: None")
    print(f"Output: {result5}")
    print(f"Length: {len(result5)}")
