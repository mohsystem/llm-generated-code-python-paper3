
import subprocess
import platform

# INSECURE: Vulnerable to command injection
def display_file_contents(filename):
    try:
        if platform.system() == "Windows":
            command = f"type {filename}"
        else:
            command = f"cat {filename}"
        
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )
        
        output = result.stdout
        if result.stderr:
            output += "ERROR: " + result.stderr
        
        return output
    
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    print("WARNING: This code is vulnerable to command injection!")
    print("Test cases:\\n")
    
    test_cases = [
        "test.txt",
        "document.log",
        "data.csv",
        "config.ini",
        "readme.md"
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test Case {i}: {test_case}")
        print(display_file_contents(test_case))
        print("---")
