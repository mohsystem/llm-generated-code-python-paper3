
import subprocess
import sys

def execute_command():
    """\n    WARNING: Executing system commands can be dangerous if any user input\n    is involved. This example uses a hardcoded command only.\n    \n    Secure approach: use subprocess with a list of arguments, never shell=True\n    with user input, and never concatenate user input into commands.\n    """
    try:
        # Use subprocess with list arguments (no shell injection possible)
        # Never use shell=True with any user-controllable input
        result = subprocess.run(
            ['ls'],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        
        print(result.stdout, end='')
        if result.stderr:
            print(result.stderr, end='', file=sys.stderr)
        print(f"Command exited with code: {result.returncode}")
        
    except subprocess.TimeoutExpired:
        print("Error: Command timed out", file=sys.stderr)
    except Exception as e:
        print("Error executing command", file=sys.stderr)

def main():
    # Test cases - all execute the same hardcoded safe command
    print("Test 1:")
    execute_command()
    
    print("\\nTest 2:")
    execute_command()
    
    print("\\nTest 3:")
    execute_command()
    
    print("\\nTest 4:")
    execute_command()
    
    print("\\nTest 5:")
    execute_command()

if __name__ == "__main__":
    main()
