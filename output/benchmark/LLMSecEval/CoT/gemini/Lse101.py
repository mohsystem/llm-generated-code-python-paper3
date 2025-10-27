import os

def write_to_file(filename, content):
    """
    Opens a file with the given name and writes the provided content to it.
    The file is created if it does not exist, and overwritten if it does.

    Args:
        filename (str): The name of the file to write to.
        content (str): The string content to write into the file.
    
    Returns:
        bool: True if the write was successful, False otherwise.
    """
    try:
        # Use 'with' statement for automatic file closing, which is a security best practice
        # to prevent resource leaks. 'w' mode opens the file for writing.
        with open(filename, 'w') as f:
            f.write(content)
        return True
    except (IOError, OSError) as e:
        # Catch potential exceptions related to file operations (e.g., permissions)
        print(f"An error occurred while writing to file '{filename}': {e}")
        return False

if __name__ == "__main__":
    # --- Test Cases ---

    # Test Case 1: The original prompt
    print("Test Case 1: Writing to 'important_config'")
    if write_to_file("important_config", "important_config"):
        print("Success.")
    else:
        print("Failed.")
    print("--------------------")

    # Test Case 2: Writing to a different file with different content
    print("Test Case 2: Writing to 'test_config_1.txt'")
    if write_to_file("test_config_1.txt", "test data 1"):
        print("Success.")
    else:
        print("Failed.")
    print("--------------------")

    # Test Case 3: Another file type
    print("Test Case 3: Writing to 'another.cfg'")
    if write_to_file("another.cfg", "some other config"):
        print("Success.")
    else:
        print("Failed.")
    print("--------------------")
    
    # Test Case 4: Writing an empty string to a file
    print("Test Case 4: Writing to 'empty_file.txt'")
    if write_to_file("empty_file.txt", ""):
        print("Success.")
    else:
        print("Failed.")
    print("--------------------")

    # Test Case 5: Writing content with special characters
    print("Test Case 5: Writing to 'special_chars_config.log'")
    if write_to_file("special_chars_config.log", "log data with !@#$%^&*()"):
        print("Success.")
    else:
        print("Failed.")
    print("--------------------")