
import random
import string
import threading

class Task184:
    _used_names = set()
    _lock = threading.Lock()
    _MAX_NAMES = 26 * 26 * 1000  # 676,000 possible names
    
    def __init__(self):
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
        letters = ''.join(random.choices(string.ascii_uppercase, k=2))
        numbers = ''.join(random.choices(string.digits, k=3))
        return letters + numbers
    
    def get_name(self):
        return self._name
    
    def reset(self):
        with self._lock:
            Task184._used_names.discard(self._name)
            self._name = self._generate_unique_name()


if __name__ == "__main__":
    print("Test Case 1: Creating new robots")
    robot1 = Task184()
    robot2 = Task184()
    print(f"Robot 1: {robot1.get_name()}")
    print(f"Robot 2: {robot2.get_name()}")
    print(f"Names are unique: {robot1.get_name() != robot2.get_name()}")
    
    print("\\nTest Case 2: Resetting a robot")
    old_name = robot1.get_name()
    robot1.reset()
    new_name = robot1.get_name()
    print(f"Old name: {old_name}")
    print(f"New name: {new_name}")
    print(f"Names are different: {old_name != new_name}")
    
    print("\\nTest Case 3: Creating multiple robots")
    robots = [Task184() for _ in range(5)]
    names = set()
    for robot in robots:
        name = robot.get_name()
        names.add(name)
        print(f"Robot: {name}")
    print(f"All names unique: {len(names) == len(robots)}")
    
    print("\\nTest Case 4: Resetting multiple robots")
    for robot in robots:
        before = robot.get_name()
        robot.reset()
        print(f"{before} -> {robot.get_name()}")
    
    print("\\nTest Case 5: Verify name format")
    robot3 = Task184()
    test_name = robot3.get_name()
    import re
    valid_format = bool(re.match(r'^[A-Z]{2}\\d{3}$', test_name))
    print(f"Robot name: {test_name}")
    print(f"Valid format (2 letters + 3 digits): {valid_format}")
