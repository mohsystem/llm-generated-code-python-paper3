import secrets
import threading
import string

class Robot:
    _used_names = set()
    _lock = threading.Lock()

    def __init__(self):
        self._name = None

    @property
    def name(self):
        if self._name is None:
            self._name = self._generate_unique_name()
        return self._name

    def reset(self):
        if self._name is not None:
            with Robot._lock:
                if self._name in Robot._used_names:
                    Robot._used_names.remove(self._name)
            self._name = None

    @staticmethod
    def _generate_unique_name():
        while True:
            letter1 = secrets.choice(string.ascii_uppercase)
            letter2 = secrets.choice(string.ascii_uppercase)
            number = secrets.randbelow(1000)
            new_name = f"{letter1}{letter2}{number:03d}"

            with Robot._lock:
                if new_name not in Robot._used_names:
                    Robot._used_names.add(new_name)
                    return new_name

def main():
    # Test Case 1: Create a robot and get its name
    robot1 = Robot()
    name1 = robot1.name
    print(f"Test Case 1: Robot 1's first name: {name1}")

    # Test Case 2: Get the same robot's name again, should be the same
    name1_again = robot1.name
    print(f"Test Case 2: Robot 1's name again: {name1_again}")
    print(f"Name is consistent: {name1 == name1_again}")

    # Test Case 3: Create a second robot, its name should be different
    robot2 = Robot()
    name2 = robot2.name
    print(f"Test Case 3: Robot 2's name: {name2}")
    print(f"Names are unique: {name1 != name2}")

    # Test Case 4: Reset the first robot and get its new name
    print("Test Case 4: Resetting Robot 1...")
    robot1.reset()
    new_name1 = robot1.name
    print(f"Robot 1's new name: {new_name1}")
    print(f"New name is different from old name: {name1 != new_name1}")
    print(f"New name is unique from Robot 2: {new_name1 != name2}")

    # Test Case 5: Create more robots
    print("Test Case 5: Creating more robots...")
    robot3 = Robot()
    robot4 = Robot()
    print(f"Robot 3's name: {robot3.name}")
    print(f"Robot 4's name: {robot4.name}")

if __name__ == "__main__":
    main()