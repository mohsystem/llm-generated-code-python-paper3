
import subprocess
import sys

def execute_command(user_input):
    """\n    Vulnerable function that executes OS command with user input\n    WARNING: This demonstrates a security vulnerability\n    """
    try:
        # Vulnerable: Direct use of user input in OS command
        command = f"echo {user_input}"
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout.strip()
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    print("=== OS Command Injection Demo ===\\n")
    
    # Test case 1: Normal input
    print("Test 1 - Normal input:")
    print("Input: 'Hello World'")
    print(f"Output: {execute_command('Hello World')}")
    print()
    
    # Test case 2: Simple text
    print("Test 2 - Simple text:")
    print("Input: 'Testing123'")
    print(f"Output: {execute_command('Testing123')}")
    print()
    
    # Test case 3: Number input
    print("Test 3 - Number input:")
    print("Input: '42'")
    print(f"Output: {execute_command('42')}")
    print()
    
    # Test case 4: Special characters
    print("Test 4 - Special characters:")
    print("Input: 'test@example.com'")
    print(f"Output: {execute_command('test@example.com')}")
    print()
    
    # Test case 5: Multiple words
    print("Test 5 - Multiple words:")
    print("Input: 'This is a test'")
    print(f"Output: {execute_command('This is a test')}")
    print()

if __name__ == "__main__":
    main()
