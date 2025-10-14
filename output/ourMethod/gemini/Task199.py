import typing

class Clock:
    MINUTES_PER_HOUR = 60
    HOURS_PER_DAY = 24
    MINUTES_PER_DAY = HOURS_PER_DAY * MINUTES_PER_HOUR

    def __init__(self, hour: int, minute: int):
        effective_total_minutes = hour * self.MINUTES_PER_HOUR + minute
        # Python's % operator handles negative numbers such that the result
        # has the same sign as the divisor. For a positive divisor, this
        # automatically handles wrapping correctly.
        self.total_minutes = effective_total_minutes % self.MINUTES_PER_DAY

    def __str__(self) -> str:
        hour = self.total_minutes // self.MINUTES_PER_HOUR
        minute = self.total_minutes % self.MINUTES_PER_HOUR
        return f"{hour:02d}:{minute:02d}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Clock):
            return NotImplemented
        return self.total_minutes == other.total_minutes

    def add(self, minutes: int) -> 'Clock':
        return Clock(0, self.total_minutes + minutes)

    def subtract(self, minutes: int) -> 'Clock':
        return Clock(0, self.total_minutes - minutes)

def main():
    # Test Case 1: Create a clock and check its string representation
    clock1 = Clock(10, 30)
    print(f"Test 1: Create 10:30 -> {clock1}")

    # Test Case 2: Add minutes
    clock2 = clock1.add(70)
    print(f"Test 2: 10:30 + 70 min -> {clock2}")

    # Test Case 3: Subtract minutes, wrapping backwards
    clock3 = Clock(0, 15).subtract(30)
    print(f"Test 3: 00:15 - 30 min -> {clock3}")

    # Test Case 4: Equality check with different but equivalent inputs
    clock4a = Clock(14, 0)
    clock4b = Clock(13, 60)
    print(f"Test 4: 14:00 equals 13:60 -> {clock4a == clock4b}")

    # Test Case 5: Add minutes, wrapping forwards past midnight
    clock5 = Clock(23, 50).add(20)
    print(f"Test 5: 23:50 + 20 min -> {clock5}")

if __name__ == "__main__":
    main()