import random
import string

class Task184:
    _used_names = set()

    def __init__(self):
        self.name = None
        self.reset()

    def get_name(self):
        return self.name

    def reset(self):
        if self.name is not None and self.name in Task184._used_names:
            Task184._used_names.remove(self.name)
        
        new_name = self._generate_unique_name()
        Task184._used_names.add(new_name)
        self.name = new_name
    
    def _generate_random_name(self):
        letters = ''.join(random.choices(string.ascii_uppercase, k=2))
        digits = f"{random.randint(0, 999):03d}"
        return letters + digits

    def _generate_unique_name(self):
        while True:
            name = self._generate_random_name()
            if name not in Task184._used_names:
                return name

def main():
    print("--- Test Case 1: Create 5 robots ---")
    r1 = Task184()
    r2 = Task184()
    r3 = Task184()
    r4 = Task184()
    r5 = Task184()

    print(f"Robot 1 name: {r1.get_name()}")
    print(f"Robot 2 name: {r2.get_name()}")
    print(f"Robot 3 name: {r3.get_name()}")
    print(f"Robot 4 name: {r4.get_name()}")
    print(f"Robot 5 name: {r5.get_name()}")

    print("\n--- Test Case 2: Reset Robot 3 ---")
    old_name_r3 = r3.get_name()
    r3.reset()
    print(f"Robot 3 old name: {old_name_r3}")
    print(f"Robot 3 new name: {r3.get_name()}")
    
    print("\n--- Test Case 3: Reset Robot 1 ---")
    old_name_r1 = r1.get_name()
    r1.reset()
    print(f"Robot 1 old name: {old_name_r1}")
    print(f"Robot 1 new name: {r1.get_name()}")

    print("\n--- Test Case 4: Show current names ---")
    print(f"Robot 1 name: {r1.get_name()}")
    print(f"Robot 2 name: {r2.get_name()}")
    print(f"Robot 3 name: {r3.get_name()}")
    print(f"Robot 4 name: {r4.get_name()}")
    print(f"Robot 5 name: {r5.get_name()}")
    
    print("\n--- Test Case 5: Create a new robot ---")
    r6 = Task184()
    print(f"New Robot 6 name: {r6.get_name()}")
    print(f"Total unique names in use: {len(Task184._used_names)}")

if __name__ == "__main__":
    main()