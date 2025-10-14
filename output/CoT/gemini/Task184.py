import random
import string

class Robot:
    _used_names = set()

    def __init__(self):
        self._name = None

    @property
    def name(self):
        if self._name is None:
            self._name = self._generate_unique_name()
        return self._name

    def reset(self):
        if self._name is not None:
            Robot._used_names.discard(self._name)
            self._name = None

    def _generate_unique_name(self):
        while True:
            new_name = self._generate_random_name()
            if new_name not in Robot._used_names:
                Robot._used_names.add(new_name)
                return new_name

    @staticmethod
    def _generate_random_name():
        letters = ''.join(random.choices(string.ascii_uppercase, k=2))
        digits = ''.join(random.choices(string.digits, k=3))
        return f"{letters}{digits}"

class Task184:
    @staticmethod
    def main():
        # Test Case 1: Create a robot and get its name
        print("--- Test Case 1 ---")
        r1 = Robot()
        print(f"Robot 1 initial name: {r1.name}")
        print(f"Robot 1 name again: {r1.name}")

        # Test Case 2: Create another robot
        print("\n--- Test Case 2 ---")
        r2 = Robot()
        print(f"Robot 2 initial name: {r2.name}")

        # Test Case 3: Reset the first robot and get a new name
        print("\n--- Test Case 3 ---")
        print("Resetting Robot 1...")
        r1.reset()
        print(f"Robot 1 new name: {r1.name}")

        # Test Case 4: Create a few more robots
        print("\n--- Test Case 4 ---")
        r3 = Robot()
        r4 = Robot()
        print(f"Robot 3 name: {r3.name}")
        print(f"Robot 4 name: {r4.name}")

        # Test Case 5: Reset r2 and r3
        print("\n--- Test Case 5 ---")
        print("Resetting Robot 2 and 3...")
        r2.reset()
        r3.reset()
        print(f"Robot 2 new name: {r2.name}")
        print(f"Robot 3 new name: {r3.name}")
        print(f"Robot 1 current name: {r1.name}")
        print(f"Robot 4 current name: {r4.name}")

if __name__ == "__main__":
    Task184.main()