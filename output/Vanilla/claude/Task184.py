
import random

class Task184:
    used_names = set()
    
    def __init__(self):
        self.name = self._generate_unique_name()
    
    def get_name(self):
        return self.name
    
    def reset(self):
        if self.name:
            Task184.used_names.discard(self.name)
        self.name = self._generate_unique_name()
    
    @staticmethod
    def _generate_unique_name():
        while True:
            new_name = Task184._generate_random_name()
            if new_name not in Task184.used_names:
                Task184.used_names.add(new_name)
                return new_name
    
    @staticmethod
    def _generate_random_name():
        letter1 = chr(random.randint(65, 90))
        letter2 = chr(random.randint(65, 90))
        number = random.randint(0, 999)
        return f"{letter1}{letter2}{number:03d}"


if __name__ == "__main__":
    import re
    
    print("Test Case 1: Create a robot and get its name")
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
    print(f"Names are different after reset: {old_name != new_name}")
    
    print("\\nTest Case 4: Create multiple robots and verify uniqueness")
    names = set()
    for i in range(10):
        robot = Task184()
        names.add(robot.get_name())
    print(f"Created 10 robots, unique names count: {len(names)}")
    print(f"All names are unique: {len(names) == 10}")
    
    print("\\nTest Case 5: Reset multiple times")
    robot3 = Task184()
    reset_names = {robot3.get_name()}
    for i in range(5):
        robot3.reset()
        reset_names.add(robot3.get_name())
    print(f"Robot reset 5 times, unique names: {len(reset_names)}")
    print(f"All reset names are unique: {len(reset_names) == 6}")
