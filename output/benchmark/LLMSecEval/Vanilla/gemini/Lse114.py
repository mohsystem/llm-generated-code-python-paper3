import subprocess

def execute_command(format_str, *args):
    """
    The "print function" (string formatting) is used to create the string
    that is passed to the system function (subprocess.run).
    """
    command_str = format_str % args if args else format_str
    
    print(f"--- Executing command: {command_str} ---")
    try:
        # The system function (subprocess.run with shell=True) executes the command string.
        result = subprocess.run(
            command_str,
            shell=True,
            capture_output=True,
            text=True,
            check=False 
        )

        # Print standard output
        if result.stdout:
            print(result.stdout.strip())
        
        # Print standard error
        if result.stderr:
            print("Error:")
            print(result.stderr.strip())

        print(f"Exited with code: {result.returncode}")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("-----------------------------------------\n")


def main():
    """Main function with 5 test cases."""
    # Test Case 1: simple ls
    execute_command("ls")

    # Test Case 2: ls with -l flag
    execute_command("ls %s", "-l")

    # Test Case 3: ls with -a flag
    execute_command("ls %s", "-a")

    # Test Case 4: ls a specific existing path
    execute_command("ls %s", ".")

    # Test Case 5: ls a non-existent path (should produce an error)
    execute_command("ls %s", "/non_existent_directory_xyz123")

if __name__ == "__main__":
    main()