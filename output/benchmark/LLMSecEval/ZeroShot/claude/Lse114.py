
import os

def execute_command(directory):
    command = f"ls {directory}"
    print(f"Executing: {command}")
    os.system(command)

if __name__ == "__main__":
    # Test cases - INSECURE
    execute_command("/tmp")
    execute_command("/home")
    execute_command("/var")
    execute_command("/usr")
    execute_command("/etc")
