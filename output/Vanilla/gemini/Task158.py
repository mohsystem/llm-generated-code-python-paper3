import os
import platform

def execute_command(user_input):
    """
    Executes an OS command using user-provided input.
    This function is vulnerable to command injection because it uses os.system(),
    which passes the constructed command string directly to the system's shell.

    :param user_input: The data provided by the user, intended to be a hostname or IP.
    """
    print(f"--- Executing with input: \"{user_input}\" ---")
    
    os_name = platform.system().lower()
    
    # Construct the command string by concatenating user input
    if 'windows' in os_name:
        # Use -n for packet count on Windows
        command = f"ping -n 1 {user_input}"
    else:
        # Use -c for packet count on Unix-like systems
        command = f"ping -c 1 {user_input}"
        
    print(f"Executing command: {command}")
    
    # os.system() is a classic example of a function that can lead to command injection
    os.system(command)
    
    print("--------------------------------------------------\n")


if __name__ == "__main__":
    # 5 test cases to demonstrate the functionality and vulnerability
    test_cases = [
        "google.com",                       # Case 1: Valid hostname
        "127.0.0.1",                        # Case 2: Valid IP address
        "invalidhostname",                  # Case 3: Invalid input
        "8.8.8.8; whoami",                  # Case 4: Command injection for Unix-like systems
        "8.8.8.8 & ver"                     # Case 5: Command injection for Windows
    ]

    for test_case in test_cases:
        execute_command(test_case)