import subprocess
import platform

def secure_execute_command(user_input):
    """
    Executes an OS command securely using user-provided data.
    This function avoids command injection by passing arguments as a list
    to subprocess.run(), with shell=False (the default). The user_input
    is treated as a single, literal argument.

    :param user_input: The data provided by the user, to be used as an argument.
    """
    print(f"--- Executing command with input: \"{user_input}\" ---")

    # Basic validation
    if not user_input or not user_input.strip():
        print("Error: Input cannot be null or empty.")
        print("--------------------------------------------------\n")
        return

    # Determine the ping command based on the operating system
    # -n for Windows, -c for others (Linux/macOS)
    count_option = "-n" if platform.system().lower() == "windows" else "-c"
    
    # The command and its arguments are passed as a list.
    # This prevents the shell from interpreting the user_input string.
    command = ["ping", count_option, "1", user_input]

    try:
        # shell=False is the default and is crucial for security.
        # The user_input is passed as a single element in the list,
        # preventing it from being interpreted as multiple arguments or commands.
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
            
        print(f"Exit Code: {result.returncode}")

    except FileNotFoundError:
        print(f"Error: Command '{command[0]}' not found. Is it in your PATH?")
    except subprocess.TimeoutExpired:
        print("Error: Command timed out.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        
    print("--------------------------------------------------\n")


if __name__ == "__main__":
    # Test Case 1: Benign, valid input
    secure_execute_command("8.8.8.8")

    # Test Case 2: Another benign, valid input
    secure_execute_command("localhost")

    # Test Case 3: Malicious input attempt (Unix style)
    # This will fail to ping a host named "127.0.0.1; ls" but will NOT execute "ls"
    secure_execute_command("127.0.0.1; ls")

    # Test Case 4: Malicious input attempt (Windows style)
    # This will fail to ping a host named "127.0.0.1 && dir" but will NOT execute "dir"
    secure_execute_command("127.0.0.1 && dir")

    # Test Case 5: Input with spaces that should be treated as a single argument
    # This will likely fail, but demonstrates it's not splitting the argument.
    secure_execute_command("not a valid hostname")