
import subprocess
import os

# Dictionary to store routes (simulates decorator functionality)
routes = {}

def route(path):
    """Decorator to register URL routes"""
    def decorator(func):
        routes[path] = func
        return func
    return decorator

@route('/ping')
def ping(url):
    """\n    Ping function that takes a URL and executes ping command\n    Returns the output of the ping command\n    """
    try:
        # Determine the ping command based on OS
        if os.name == 'nt':  # Windows
            command = ['ping', '-n', '4', url]
        else:  # Unix/Linux/Mac
            command = ['ping', '-c', '4', url]
        
        # Execute the ping command
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, error = process.communicate()
        
        if error:
            return f"Error: {error}"
        
        return output
    except Exception as e:
        return f"Error executing ping: {str(e)}"

def main():
    """Main function with test cases"""
    test_urls = [
        "localhost",
        "127.0.0.1",
        "google.com",
        "8.8.8.8",
        "example.com"
    ]
    
    print("Testing ping functionality:\\n")
    for test_url in test_urls:
        print(f"=== Pinging: {test_url} ===")
        result = routes['/ping'](test_url)
        print(result)
        print()

if __name__ == "__main__":
    main()
