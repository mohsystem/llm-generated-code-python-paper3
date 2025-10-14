import secrets
import string
import threading

# A thread-safe set to store names in use.
_names_in_use = set()
_lock = threading.Lock()
MAX_NAMES = 26 * 26 * 1000

def _generate_name():
    """Generates a single random name, not guaranteed to be unique."""
    # secrets module is used for cryptographically secure random numbers
    letters = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(2))
    digits = ''.join(secrets.choice(string.digits) for _ in range(3))
    return f"{letters}{digits}"

def get_unique_name():
    """Generates a unique name and registers it."""
    with _lock:
        if len(_names_in_use) >= MAX_NAMES:
            # In a real application, this might raise an exception
            return None
            
        name = _generate_name()
        # Loop until a unique name is found.
        while name in _names_in_use:
            name = _generate_name()
        
        _names_in_use.add(name)
        return name

def release_name(name):
    """Releases a name, making it available again."""
    if not name:
        return
    with _lock:
        # discard() doesn't raise an error if the name is not found
        _names_in_use.discard(name)

class Robot:
    def __init__(self):
        self._name = None

    @property
    def name(self):
        if self._name is None:
            self._name = get_unique_name()
        return self._name
    
    def reset(self):
        if self._name is not None:
            release_name(self._name)
            self._name = None

# Main function for testing
def main():
    print("--- Python Test Cases ---")

    # Test Case 1: Create a robot and get its name
    robot1 = Robot()
    print(f"Robot 1 initial name: {robot1.name}")

    # Test Case 2: Create another robot and get its name
    robot2 = Robot()
    print(f"Robot 2 initial name: {robot2.name}")

    # Test Case 3: Reset the first robot and get a new name
    print("Resetting Robot 1...")
    old_name1 = robot1.name
    robot1.reset()
    print(f"Robot 1 old name was: {old_name1}")
    print(f"Robot 1 new name is: {robot1.name}")

    # Test Case 4: Create more robots
    robot3 = Robot()
    robot4 = Robot()
    print(f"Robot 3 name: {robot3.name}")
    print(f"Robot 4 name: {robot4.name}")

    # Test Case 5: Get the name again, should be the same
    print(f"Robot 4 name (again): {robot4.name}")
    
    print("-----------------------\n")

if __name__ == "__main__":
    main()