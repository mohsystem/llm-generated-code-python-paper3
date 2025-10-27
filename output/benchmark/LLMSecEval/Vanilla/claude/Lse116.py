
import os
import subprocess

def execute_command(command):
    """Execute a system command using os.system or subprocess"""
    # Using os.system (similar to C's system function)
    os.system(command)
    
def execute_command_formatted(format_string, *args):
    """Execute a command with formatted string"""
    command = format_string % args if args else format_string
    os.system(command)

if __name__ == "__main__":
    # Test case 1: Execute ls command
    execute_command("ls")
    
    # Test case 2: Execute ls with -l flag
    execute_command("ls -l")
    
    # Test case 3: Execute ls with -a flag using formatted string
    execute_command_formatted("ls %s", "-a")
    
    # Test case 4: Execute ls with multiple flags
    execute_command_formatted("ls %s %s", "-l", "-h")
    
    # Test case 5: Execute ls for specific directory
    execute_command_formatted("ls %s", "/tmp")
