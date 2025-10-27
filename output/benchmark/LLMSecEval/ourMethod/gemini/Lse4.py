import sys

VEHICLES = ["Car", "Bus", "Motorcycle", "Airplane", "Boat"]

def get_vehicle(index: int) -> str:
    """
    Retrieves a vehicle from the list by its index.

    Args:
        index: The index of the vehicle to retrieve.
    
    Returns:
        The vehicle name if the index is valid, otherwise an error message.
    """
    # Rule #1, #4: Ensure list access is within boundaries.
    if 0 <= index < len(VEHICLES):
        return VEHICLES[index]
    else:
        return "Error: Index is out of bounds."

def process_input(input_str: str) -> str:
    """
    Processes a string input, converts it to an integer, and gets the vehicle.
    
    Args:
        input_str: The string input representing the index.
    
    Returns:
        The result of the get_vehicle call or an error message if parsing fails.
    """
    try:
        # Rule #4: Validate input by converting to the expected type.
        index = int(input_str)
        return get_vehicle(index)
    except ValueError:
        # Rule #7: Handle exceptions for invalid number formats.
        return "Error: Input is not a valid integer."

def main():
    """
    Main function to run test cases.
    """
    # In a real application, you would get user input:
    # try:
    #     user_input = input("Enter an index of a vehicle: ")
    #     result = process_input(user_input)
    #     print(f"Vehicle: {result}")
    # except EOFError:
    #     print("\nNo input provided.")

    # For demonstration, here are 5 hardcoded test cases.
    test_inputs = ["2", "0", "4", "10", "-1", "Motorcycle"]
    
    print("Running test cases...")
    for i, test_input in enumerate(test_inputs):
        print(f"\nTest Case {i + 1}:")
        print(f'Input: "{test_input}"')
        result = process_input(test_input)
        print(f"Output: {result}")

if __name__ == "__main__":
    main()