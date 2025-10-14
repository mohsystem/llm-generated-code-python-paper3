
import re
from typing import List, Union

class Task45:
    MAX_INPUT_LENGTH = 1000
    ALPHANUMERIC_PATTERN = re.compile(r'^[a-zA-Z0-9\\s]+$')
    
    @staticmethod
    def calculator(operation: str, num1: float, num2: float) -> float:
        """Secure calculator with input validation"""
        if operation is None or not operation.strip():
            raise ValueError("Operation cannot be None or empty")
        
        if not isinstance(num1, (int, float)) or not isinstance(num2, (int, float)):
            raise TypeError("Numbers must be numeric types")
        
        if not (-1e308 < num1 < 1e308) or not (-1e308 < num2 < 1e308):
            raise ValueError("Number out of valid range")
        
        operation = operation.lower().strip()
        
        if operation == "add":
            return num1 + num2
        elif operation == "subtract":
            return num1 - num2
        elif operation == "multiply":
            return num1 * num2
        elif operation == "divide":
            if num2 == 0:
                raise ZeroDivisionError("Division by zero is not allowed")
            return num1 / num2
        else:
            raise ValueError(f"Invalid operation: {operation}")
    
    @staticmethod
    def validate_input(input_str: str) -> bool:
        """Secure string validator with length and character checks"""
        if input_str is None:
            raise ValueError("Input cannot be None")
        
        if len(input_str) > Task45.MAX_INPUT_LENGTH:
            raise ValueError("Input exceeds maximum allowed length")
        
        return bool(Task45.ALPHANUMERIC_PATTERN.match(input_str))
    
    @staticmethod
    def process_array(arr: List[int], index: int) -> int:
        """Secure array processor with bounds checking"""
        if arr is None:
            raise ValueError("Array cannot be None")
        
        if len(arr) == 0:
            raise ValueError("Array cannot be empty")
        
        if not isinstance(index, int):
            raise TypeError("Index must be an integer")
        
        if index < 0 or index >= len(arr):
            raise IndexError(f"Index {index} is out of bounds for array length {len(arr)}")
        
        return arr[index] * 2
    
    @staticmethod
    def parse_secure_integer(input_str: str) -> int:
        """Secure string parser with error handling"""
        if input_str is None or not input_str.strip():
            raise ValueError("Input cannot be None or empty")
        
        trimmed = input_str.strip()
        
        if len(trimmed) > 10:
            raise ValueError("Input string too long for integer parsing")
        
        try:
            return int(trimmed)
        except ValueError as e:
            raise ValueError(f"Invalid integer format: {trimmed}") from e


def main():
    print("=== Test Case 1: Calculator Operations ===")
    try:
        print(f"Add 10 + 5 = {Task45.calculator('add', 10, 5)}")
        print(f"Divide 20 / 4 = {Task45.calculator('divide', 20, 4)}")
    except Exception as e:
        print(f"Error: {e}")
    
    print("\\n=== Test Case 2: Division by Zero ===")
    try:
        Task45.calculator("divide", 10, 0)
    except ZeroDivisionError as e:
        print(f"Caught expected error: {e}")
    
    print("\\n=== Test Case 3: Input Validation ===")
    try:
        print(f"Valid input 'Hello123': {Task45.validate_input('Hello123')}")
        print(f"Invalid input 'Hello@123': {Task45.validate_input('Hello@123')}")
    except Exception as e:
        print(f"Error: {e}")
    
    print("\\n=== Test Case 4: Array Processing ===")
    try:
        test_array = [1, 2, 3, 4, 5]
        print(f"Process array[2] = {Task45.process_array(test_array, 2)}")
        print(f"Process array[10] = {Task45.process_array(test_array, 10)}")
    except IndexError as e:
        print(f"Caught expected error: {e}")
    
    print("\\n=== Test Case 5: String Parsing ===")
    try:
        print(f"Parse '123' = {Task45.parse_secure_integer('123')}")
        print(f"Parse 'abc' = {Task45.parse_secure_integer('abc')}")
    except ValueError as e:
        print(f"Caught expected error: {e}")


if __name__ == "__main__":
    main()
