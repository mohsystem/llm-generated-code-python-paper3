
import math

def perform_operation(operation, num1, num2):
    try:
        operation = operation.lower()
        
        if operation == "add":
            return str(num1 + num2)
        elif operation == "subtract":
            return str(num1 - num2)
        elif operation == "multiply":
            return str(num1 * num2)
        elif operation == "divide":
            if num2 == 0:
                raise ZeroDivisionError("Division by zero")
            return str(num1 / num2)
        elif operation == "modulo":
            if num2 == 0:
                raise ZeroDivisionError("Modulo by zero")
            return str(num1 % num2)
        elif operation == "power":
            return str(math.pow(num1, num2))
        else:
            raise ValueError(f"Invalid operation: {operation}")
            
    except ZeroDivisionError as e:
        return f"Error: {str(e)}"
    except ValueError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Error: Unexpected error occurred - {str(e)}"


def parse_and_calculate(input_str):
    try:
        if input_str is None or not input_str.strip():
            raise ValueError("Input cannot be empty")
        
        parts = input_str.strip().split()
        
        if len(parts) != 3:
            raise ValueError("Invalid input format. Expected: <operation> <num1> <num2>")
        
        operation = parts[0]
        num1 = float(parts[1])
        num2 = float(parts[2])
        
        return perform_operation(operation, num1, num2)
        
    except ValueError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Error: Unexpected error - {str(e)}"


def validate_and_process(inputs):
    try:
        if inputs is None or len(inputs) == 0:
            raise ValueError("Input array is null or empty")
        
        results = []
        for i, input_str in enumerate(inputs):
            try:
                result = parse_and_calculate(input_str)
                results.append(f"Input {i + 1}: {result}")
            except Exception as e:
                results.append(f"Input {i + 1}: Error - {str(e)}")
        
        return "\\n".join(results)
        
    except ValueError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Error: Unexpected error in batch processing - {str(e)}"


if __name__ == "__main__":
    print("=== Test Case 1: Valid Addition ===")
    print(parse_and_calculate("add 10 5"))
    
    print("\\n=== Test Case 2: Division by Zero ===")
    print(parse_and_calculate("divide 10 0"))
    
    print("\\n=== Test Case 3: Invalid Operation ===")
    print(parse_and_calculate("invalid 10 5"))
    
    print("\\n=== Test Case 4: Invalid Number Format ===")
    print(parse_and_calculate("multiply abc 5"))
    
    print("\\n=== Test Case 5: Batch Processing ===")
    batch_inputs = [
        "add 100 50",
        "subtract 75 25",
        "multiply 8 7",
        "divide 100 4",
        "power 2 8"
    ]
    print(validate_and_process(batch_inputs))
