
class Task199:
    def __init__(self, hours, minutes):
        total_minutes = (hours * 60 + minutes) % (24 * 60)
        if total_minutes < 0:
            total_minutes += 24 * 60
        self.hours = total_minutes // 60
        self.minutes = total_minutes % 60
    
    def add_minutes(self, minutes_to_add):
        total_minutes = self.hours * 60 + self.minutes + minutes_to_add
        return Task199(0, total_minutes)
    
    def subtract_minutes(self, minutes_to_subtract):
        return self.add_minutes(-minutes_to_subtract)
    
    def __eq__(self, other):
        if not isinstance(other, Task199):
            return False
        return self.hours == other.hours and self.minutes == other.minutes
    
    def __hash__(self):
        return 60 * self.hours + self.minutes
    
    def __str__(self):
        return f"{self.hours:02d}:{self.minutes:02d}"


if __name__ == "__main__":
    # Test case 1: Create a clock and display it
    clock1 = Task199(10, 30)
    print(f"Test 1 - Clock at 10:30: {clock1}")
    
    # Test case 2: Add minutes
    clock2 = clock1.add_minutes(45)
    print(f"Test 2 - Add 45 minutes to 10:30: {clock2}")
    
    # Test case 3: Subtract minutes
    clock3 = clock1.subtract_minutes(90)
    print(f"Test 3 - Subtract 90 minutes from 10:30: {clock3}")
    
    # Test case 4: Wrap around midnight (add)
    clock4 = Task199(23, 45)
    clock5 = clock4.add_minutes(30)
    print(f"Test 4 - Add 30 minutes to 23:45: {clock5}")
    
    # Test case 5: Equality check
    clock6 = Task199(11, 15)
    clock7 = Task199(11, 15)
    clock8 = Task199(11, 16)
    print(f"Test 5 - 11:15 equals 11:15: {clock6 == clock7}")
    print(f"Test 5 - 11:15 equals 11:16: {clock6 == clock8}")
