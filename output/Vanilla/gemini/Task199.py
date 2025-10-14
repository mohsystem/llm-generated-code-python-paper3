class Clock:
    MINUTES_IN_DAY = 24 * 60

    def __init__(self, hour, minute):
        initial_total_minutes = hour * 60 + minute
        # Python's % handles negative numbers correctly for this use case
        self.total_minutes = initial_total_minutes % self.MINUTES_IN_DAY

    def __str__(self):
        hours = self.total_minutes // 60
        minutes = self.total_minutes % 60
        return f"{hours:02d}:{minutes:02d}"

    def add(self, minutes):
        self.total_minutes = (self.total_minutes + minutes) % self.MINUTES_IN_DAY
        return self

    def subtract(self, minutes):
        return self.add(-minutes)

    def __eq__(self, other):
        if not isinstance(other, Clock):
            return NotImplemented
        return self.total_minutes == other.total_minutes

def main():
    print("Python Test Cases:")
    
    # Test 1: Creation and ToString
    c1 = Clock(8, 0)
    print(f"Test 1: Create 08:00 -> {c1}")

    # Test 2: Equality
    c2 = Clock(8, 0)
    c3 = Clock(9, 0)
    print(f"Test 2: 08:00 == 08:00 -> {c1 == c2}")
    print(f"Test 2: 08:00 == 09:00 -> {c1 == c3}")

    # Test 3: Addition
    c4 = Clock(10, 0)
    c4.add(63)
    print(f"Test 3: 10:00 + 63 mins -> {c4}")

    # Test 4: Subtraction with rollover
    c5 = Clock(0, 30)
    c5.subtract(60)
    print(f"Test 4: 00:30 - 60 mins -> {c5}")

    # Test 5: Complex Addition with rollover
    c6 = Clock(23, 45)
    c6.add(180)
    print(f"Test 5: 23:45 + 180 mins -> {c6}")

if __name__ == "__main__":
    main()