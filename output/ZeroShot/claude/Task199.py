
class Task199:
    def __init__(self, hours, minutes):
        total_minutes = hours * 60 + minutes
        total_minutes = total_minutes % (24 * 60)
        if total_minutes < 0:
            total_minutes += 24 * 60
        self.hours = total_minutes // 60
        self.minutes = total_minutes % 60
    
    def add_minutes(self, minutes_to_add):
        total_minutes = self.hours * 60 + self.minutes + minutes_to_add
        total_minutes = total_minutes % (24 * 60)
        if total_minutes < 0:
            total_minutes += 24 * 60
        self.hours = total_minutes // 60
        self.minutes = total_minutes % 60
    
    def subtract_minutes(self, minutes_to_subtract):
        self.add_minutes(-minutes_to_subtract)
    
    def __eq__(self, other):
        if not isinstance(other, Task199):
            return False
        return self.hours == other.hours and self.minutes == other.minutes
    
    def __hash__(self):
        return hash((self.hours, self.minutes))
    
    def __str__(self):
        return f"{self.hours:02d}:{self.minutes:02d}"


if __name__ == "__main__":
    # Test case 1: Basic clock creation
    clock1 = Task199(10, 30)
    print(f"Test 1 - Clock creation: {clock1}")
    
    # Test case 2: Add minutes
    clock2 = Task199(10, 30)
    clock2.add_minutes(90)
    print(f"Test 2 - Add 90 minutes to 10:30: {clock2}")
    
    # Test case 3: Subtract minutes
    clock3 = Task199(10, 30)
    clock3.subtract_minutes(45)
    print(f"Test 3 - Subtract 45 minutes from 10:30: {clock3}")
    
    # Test case 4: Clock equality
    clock4a = Task199(15, 45)
    clock4b = Task199(15, 45)
    print(f"Test 4 - Clock equality (15:45 == 15:45): {clock4a == clock4b}")
    
    # Test case 5: Wrap around midnight
    clock5 = Task199(23, 30)
    clock5.add_minutes(45)
    print(f"Test 5 - Add 45 minutes to 23:30 (wrap around): {clock5}")
