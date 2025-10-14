
import secrets
import threading
import re

class Task184:
    _used_names = set()
    _lock = threading.Lock()
    _MAX_NAMES = 26 * 26 * 1000
    
    def __init__(self):
        self._name = self._generate_unique_name()
    
    def get_name(self):
        return self._name
    
    def reset(self):
        with Task184._lock:
            if self._name:
                Task184._used_names.discard(self._name)
            self._name = self._generate_unique_name()
    
    @classmethod
    def _generate_unique_name(cls):
        with cls._lock:
            if len(cls._used_names) >= cls._MAX_NAMES:
                raise RuntimeError("All possible robot names have been exhausted")
            
            new_name = cls._generate_random_name()
            while new_name in cls._used_names:
                new_name = cls._generate_random_name()
            
            cls._used_names.add(new_name)
            return new_name
    
    @staticmethod
    def _generate_random_name():
        letter1 = chr(ord('A') + secrets.randbelow(26))
        letter2 = chr(ord('A') + secrets.randbelow(26))
        digits = secrets.randbelow(1000)
        return f"{letter1}{letter2}{digits:03d}"


if __name__ == "__main__":
    print("Test Case 1: Create robot and get name")
    robot1 = Task184()
    name1 = robot1.get_name()
    print(f"Robot 1 name: {name1}")
    print(f"Name matches pattern: {bool(re.match(r'^[A-Z]{2}\\d{3}$', name1))}")
    
    print("\\nTest Case 2: Create another robot with different name")
    robot2 = Task184()
    name2 = robot2.get_name()
    print(f"Robot 2 name: {name2}")
    print(f"Names are different: {name1 != name2}")
    
    print("\\nTest Case 3: Reset robot and verify new name")
    old_name = robot1.get_name()
    robot1.reset()
    new_name = robot1.get_name()
    print(f"Old name: {old_name}")
    print(f"New name: {new_name}")
    print(f"Names are different: {old_name != new_name}")
    
    print("\\nTest Case 4: Create multiple robots")
    robot3 = Task184()
    robot4 = Task184()
    robot5 = Task184()
    print(f"Robot 3: {robot3.get_name()}")
    print(f"Robot 4: {robot4.get_name()}")
    print(f"Robot 5: {robot5.get_name()}")
    
    print("\\nTest Case 5: Verify uniqueness after resets")
    robot2.reset()
    robot3.reset()
    all_names = {
        robot1.get_name(),
        robot2.get_name(),
        robot3.get_name(),
        robot4.get_name(),
        robot5.get_name()
    }
    print(f"All 5 names are unique: {len(all_names) == 5}")
