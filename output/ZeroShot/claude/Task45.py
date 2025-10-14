
def perform_operation(input_str, operation):
    try:
        if input_str is None or operation is None:
            raise ValueError("Input and operation cannot be None")
        
        input_str = str(input_str).strip()
        operation = str(operation).strip().lower()
        
        if operation == "uppercase":
            return input_str.upper()
        
        elif operation == "lowercase":
            return input_str.lower()
        
        elif operation == "reverse":
            return input_str[::-1]
        
        elif operation == "length":
            return str(len(input_str))
        
        elif operation == "wordcount":
            if not input_str:
                return "0"
            return str(len(input_str.split()))
        
        elif operation == "number":
            try:
                num = float(input_str)
                return str(num * 2)
            except ValueError:
                raise ValueError("Input is not a valid number for 'number' operation")
        
        else:
            raise ValueError(f"Unknown operation: {operation}")
            
    except ValueError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Error: Unexpected error occurred - {str(e)}"


def main():
    print("=== Test Cases ===\\n")
    
    # Test case 1: Uppercase operation
    result1 = perform_operation("hello world", "uppercase")
    print(f"Test 1 - Uppercase: {result1}")
    
    # Test case 2: Reverse operation
    result2 = perform_operation("Java Programming", "reverse")
    print(f"Test 2 - Reverse: {result2}")
    
    # Test case 3: Word count operation
    result3 = perform_operation("This is a test sentence", "wordcount")
    print(f"Test 3 - Word Count: {result3}")
    
    # Test case 4: Number operation with valid input
    result4 = perform_operation("42.5", "number")
    print(f"Test 4 - Number Operation: {result4}")
    
    # Test case 5: Error handling - invalid operation
    result5 = perform_operation("test", "invalid_op")
    print(f"Test 5 - Invalid Operation: {result5}")


if __name__ == "__main__":
    main()
