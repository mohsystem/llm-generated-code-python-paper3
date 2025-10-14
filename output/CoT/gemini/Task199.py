class Task199:
    class Clock:
        MINUTES_IN_DAY = 24 * 60

        def __init__(self, hour, minute):
            total_minutes = hour * 60 + minute
            # Python's % operator handles negative numbers in a mathematically useful way for this
            total_minutes %= self.MINUTES_IN_DAY
            self.hour = total_minutes // 60
            self.minute = total_minutes % 60

        def __repr__(self):
            return f"{self.hour:02d}:{self.minute:02d}"

        def __eq__(self, other):
            if not isinstance(other, Task199.Clock):
                return NotImplemented
            return self.hour == other.hour and self.minute == other.minute

        def add(self, minutes):
            return Task199.Clock(self.hour, self.minute + minutes)

        def subtract(self, minutes):
            return Task199.Clock(self.hour, self.minute - minutes)

def run_tests():
    # Test Case 1: Simple creation and toString
    clock1 = Task199.Clock(8, 30)
    print("Test Case 1: Simple creation")
    print(f"Clock(8, 30) -> {clock1}")
    print("--------------------")

    # Test Case 2: Adding minutes without hour rollover
    clock2 = Task199.Clock(10, 0).add(25)
    print("Test Case 2: Add minutes (no rollover)")
    print(f"Clock(10, 0).add(25) -> {clock2}")
    print("--------------------")

    # Test Case 3: Adding minutes with hour and day rollover
    clock3 = Task199.Clock(23, 45).add(30)
    print("Test Case 3: Add minutes (with rollover)")
    print(f"Clock(23, 45).add(30) -> {clock3}")
    print("--------------------")

    # Test Case 4: Subtracting minutes with hour and day rollover
    clock4 = Task199.Clock(0, 10).subtract(30)
    print("Test Case 4: Subtract minutes (with rollover)")
    print(f"Clock(0, 10).subtract(30) -> {clock4}")
    print("--------------------")

    # Test Case 5: Equality and normalization
    clock5a = Task199.Clock(15, 30)
    clock5b = Task199.Clock(14, 90)
    clock5c = Task199.Clock(16, -30)
    clock5d = Task199.Clock(39, 30)
    clock5e = Task199.Clock(15, 31)
    print("Test Case 5: Equality and normalization")
    print(f"Clock(15, 30) equals Clock(14, 90)? {clock5a == clock5b}")
    print(f"Clock(15, 30) equals Clock(16, -30)? {clock5a == clock5c}")
    print(f"Clock(15, 30) equals Clock(39, 30)? {clock5a == clock5d}")
    print(f"Clock(15, 30) equals Clock(15, 31)? {clock5a == clock5e}")
    print("--------------------")

if __name__ == "__main__":
    run_tests()