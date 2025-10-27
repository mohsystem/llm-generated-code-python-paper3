
import sys

# Predefined array of vehicles
VEHICLES = ["Car", "Truck", "Motorcycle", "Bus", "Van"]

def get_vehicle_at_index(index: int) -> str:
    """\n    Safely retrieves a vehicle at the given index.\n    \n    Args:\n        index: Integer index to access the vehicles array\n        \n    Returns:\n        Vehicle name or error message\n    """
    # Input validation: check type to prevent type confusion
    if not isinstance(index, int):
        return "Error: Invalid index type"
    
    # Input validation: check bounds to prevent array index errors
    # This prevents out of bounds access vulnerabilities
    if index < 0 or index >= len(VEHICLES):
        return "Error: Invalid index"
    
    # Safe array access after validation
    return VEHICLES[index]

def main():
    try:
        # Prompt user for input
        user_input = input(f"Enter an index of a vehicle (0-{len(VEHICLES) - 1}): ")
        
        # Input validation: sanitize and convert to integer
        # Strip whitespace to prevent format-based attacks
        user_input = user_input.strip()
        
        # Validate input is numeric before conversion
        # This prevents injection and type confusion
        if not user_input.lstrip('-').isdigit():
            print("Error: Invalid input format")
            return
        
        # Convert to integer with bounds checking
        index = int(user_input)
        
        # Length validation: prevent excessively large inputs
        if len(user_input) > 10:
            print("Error: Input too long")
            return
        
        # Get vehicle using validated index
        result = get_vehicle_at_index(index)
        print(result)
        
    except ValueError:
        # Handle conversion errors - fail closed with generic message
        print("Error: Invalid input")
    except KeyboardInterrupt:
        # Handle user interrupt gracefully
        print("\\nOperation cancelled")
    except Exception:
        # Catch unexpected exceptions - fail closed without leaking details
        print("Error: An error occurred")

if __name__ == "__main__":
    # Run main program
    main()
    
    # Test cases
    print("\\n--- Test Cases ---")
    print(f"Test 1 (index 0): {get_vehicle_at_index(0)}")
    print(f"Test 2 (index 2): {get_vehicle_at_index(2)}")
    print(f"Test 3 (index 4): {get_vehicle_at_index(4)}")
    print(f"Test 4 (index -1): {get_vehicle_at_index(-1)}")
    print(f"Test 5 (index 10): {get_vehicle_at_index(10)}")
