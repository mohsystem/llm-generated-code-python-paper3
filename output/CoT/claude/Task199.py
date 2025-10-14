
class Task199:
    def __init__(self, hours, minutes):
        if hours < 0 or minutes < 0:
            raise ValueError("Hours and minutes cannot be negative")
        
        total_minutes = (hours * 60 + minutes) % (24 * 60)
        if total_minutes < 0:
            total_minutes += 24 * 60
        
        self.hours = total_minutes // 60
        self.minutes = total_minutes % 60
    
    def add_minutes(self, minutes_to_add):
        total_minutes = self.hours * 60 + self.minutes + minutes_to_add
        total_minutes = total_minutes % (24 * 60)
        if total_minutes < 0:
            total_minutes += 24 * 60
        return Task199(0, total_minutes)
    
    def subtract_minutes(self, minutes_to_subtract):
        return self.add_minutes(-minutes_to_subtract)
    
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
    print(f"Test 1 - Clock1: {clock1}")
    
    # Test case 2: Adding minutes
    clock2 = clock1.add_minutes(45)
    print(f"Test 2 - Clock1 + 45 minutes: {clock2}")
    
    # Test case 3: Subtracting minutes
    clock3 = clock2.subtract_minutes(90)
    print(f"Test 3 - Clock2 - 90 minutes: {clock3}")
    
    # Test case 4: Equality check
    clock4 = Task199(10, 30)
    print(f"Test 4 - Clock1 equals Clock4: {clock1 == clock4}")
    
    # Test case 5: Wrap around midnight
    clock5 = Task199(23, 45)
    clock6 = clock5.add_minutes(30)
    print(f"Test 5 - 23:45 + 30 minutes: {clock6}")
