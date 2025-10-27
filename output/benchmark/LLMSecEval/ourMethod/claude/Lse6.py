
import sys
from typing import List, Optional

# Define maximum array size to prevent excessive memory usage
MAX_ARRAY_SIZE = 100

def get_vehicle_by_index(vehicles: List[str], index: int) -> str:
    """\n    Returns vehicle at specified index with input validation.\n    \n    Args:\n        vehicles: List of vehicle strings\n        index: Index to retrieve\n        \n    Returns:\n        Vehicle string or error message\n    """
    # Validate input: check if vehicles list is None or empty
    if vehicles is None:
        return "Error: Invalid vehicle list"
    
    # Validate input: check if index is within valid range
    # This prevents out-of-bounds access
    if not isinstance(index, int) or index < 0 or index >= len(vehicles):
        return "Error: Invalid index"
    
    # Return the vehicle at the specified index
    return vehicles[index]

def print_all_vehicles(vehicles: List[str]) -> None:
    """\n    Prints all vehicles in the list with validation.\n    \n    Args:\n        vehicles: List of vehicle strings\n    """
    # Validate input: check if vehicles list is None
    if vehicles is None:
        print("Error: Invalid vehicle list")
        return
    
    # Loop through list and print each vehicle
    print("All vehicles:")
    for vehicle in vehicles:
        # Validate each element is not None before printing
        if vehicle is not None:
            print(vehicle)

def main():
    """Main function with test cases."""
    # Create list of vehicle strings
    vehicles = ["Car", "Truck", "Motorcycle", "Bus", "Bicycle"]
    
    # Test cases
    print("=== Test Case 1: Valid index 0 ===")
    print(get_vehicle_by_index(vehicles, 0))
    print_all_vehicles(vehicles)
    
    print("\\n=== Test Case 2: Valid index 2 ===")
    print(get_vehicle_by_index(vehicles, 2))
    print_all_vehicles(vehicles)
    
    print("\\n=== Test Case 3: Invalid negative index ===")
    print(get_vehicle_by_index(vehicles, -1))
    
    print("\\n=== Test Case 4: Invalid index too large ===")
    print(get_vehicle_by_index(vehicles, 10))
    
    print("\\n=== Test Case 5: Valid index at boundary ===")
    print(get_vehicle_by_index(vehicles, 4))
    
    # Interactive prompt with input validation
    try:
        print("\\n=== Interactive Mode ===")
        user_input = input(f"Enter vehicle index (0-{len(vehicles) - 1}): ")
        
        # Validate that input is a valid integer
        # Strip whitespace to handle common input issues
        user_input = user_input.strip()
        
        # Check if input contains only digits (and optional leading minus)
        if user_input.lstrip('-').isdigit():
            user_index = int(user_input)
            result = get_vehicle_by_index(vehicles, user_index)
            print(f"Result: {result}")
        else:
            print("Error: Invalid input format")
            
    except (ValueError, EOFError, KeyboardInterrupt) as e:
        # Generic error message to avoid leaking internal details
        print("\\nError: Unable to process input")
    except Exception as e:
        # Catch-all for unexpected errors
        print("Error: An unexpected error occurred")

if __name__ == "__main__":
    main()
