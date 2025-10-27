
import subprocess
import sys

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error executing command: {str(e)}"

def format_command(format_string, *args):
    return format_string % args

if __name__ == "__main__":
    # Test case 1: List current directory
    cmd1 = format_command("ls %s", ".")
    print(f"Test 1: {cmd1}")
    print(execute_command(cmd1))

    # Test case 2: List with -l flag
    cmd2 = format_command("ls %s", "-l")
    print(f"Test 2: {cmd2}")
    print(execute_command(cmd2))

    # Test case 3: List with -a flag
    cmd3 = format_command("ls %s", "-a")
    print(f"Test 3: {cmd3}")
    print(execute_command(cmd3))

    # Test case 4: List with -la flags
    cmd4 = format_command("ls %s %s", "-l", "-a")
    print(f"Test 4: {cmd4}")
    print(execute_command(cmd4))

    # Test case 5: List specific directory
    cmd5 = format_command("ls %s", "/tmp")
    print(f"Test 5: {cmd5}")
    print(execute_command(cmd5))
