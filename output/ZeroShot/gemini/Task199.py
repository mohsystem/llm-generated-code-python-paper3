class Task199:
    MINUTES_PER_HOUR = 60
    HOURS_PER_DAY = 24
    MINUTES_PER_DAY = MINUTES_PER_HOUR * HOURS_PER_DAY

    def __init__(self, hour, minute):
        total = hour * self.MINUTES_PER_HOUR + minute
        # Python's % operator handles negative numbers conveniently
        self.total_minutes = total % self.MINUTES_PER_DAY

    def add(self, minutes):
        self.total_minutes = (self.total_minutes + minutes) % self.MINUTES_PER_DAY

    def subtract(self, minutes):
        self.add(-minutes)

    def __str__(self):
        hour = self.total_minutes // self.MINUTES_PER_HOUR
        minute = self.total_minutes % self.MINUTES_PER_HOUR
        return f"{hour:02d}:{minute:02d}"

    def __eq__(self, other):
        if not isinstance(other, Task199):
            return NotImplemented
        return self.total_minutes == other.total_minutes

def main():
    # Test Case 1: Create a clock and test toString
    clock1 = Task199(10, 30)
    print(f"Test Case 1: Create clock (10:30) -> {clock1}")

    # Test Case 2: Add minutes without day rollover
    clock1.add(20)
    print(f"Test Case 2: Add 20 mins to 10:30 -> {clock1}")

    # Test Case 3: Add minutes with day rollover
    clock2 = Task199(23, 50)
    clock2.add(20)
    print(f"Test Case 3: Add 20 mins to 23:50 -> {clock2}")

    # Test Case 4: Subtract minutes with day rollover
    clock3 = Task199(0, 10)
    clock3.subtract(20)
    print(f"Test Case 4: Subtract 20 mins from 00:10 -> {clock3}")
    
    # Test Case 5: Equality
    clockA = Task199(14, 30)
    clockB = Task199(14, 30)
    clockC = Task199(10, 0)
    clockD = Task199(38, 30) # equivalent to 14:30
    print("Test Case 5: Equality Check")
    print(f"  14:30 == 14:30 -> {clockA == clockB}")
    print(f"  14:30 == 10:00 -> {clockA == clockC}")
    print(f"  14:30 == normalized 38:30 -> {clockA == clockD}")

if __name__ == "__main__":
    main()