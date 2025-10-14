class Clock:
    # Immutable-like clock (operations return new instances)
    __slots__ = ("_minutes",)

    def __init__(self, hour: int, minute: int):
        total = hour * 60 + minute
        self._minutes = total % 1440

    @staticmethod
    def of(hour: int, minute: int):
        return Clock(hour, minute)

    def plus(self, minutes_to_add: int):
        return Clock(0, (self._minutes + minutes_to_add) % 1440)

    def minus(self, minutes_to_sub: int):
        return Clock(0, (self._minutes - minutes_to_sub) % 1440)

    def __str__(self) -> str:
        h = self._minutes // 60
        m = self._minutes % 60
        return f"{h:02d}:{m:02d}"

    def __eq__(self, other) -> bool:
        if not isinstance(other, Clock):
            return False
        return self._minutes == other._minutes


if __name__ == "__main__":
    # Test 1: Basic creation and toString
    c1 = Clock.of(10, 37)
    print("Test1:", str(c1))  # Expected 10:37

    # Test 2: Add minutes with hour rollover
    c2 = Clock.of(10, 0).plus(3)
    print("Test2:", str(c2))  # Expected 10:03

    # Test 3: Add minutes across midnight
    c3 = Clock.of(23, 59).plus(2)
    print("Test3:", str(c3))  # Expected 00:01

    # Test 4: Subtract minutes across midnight
    c4 = Clock.of(0, 5).minus(10)
    print("Test4:", str(c4))  # Expected 23:55

    # Test 5: Equality of clocks representing same time
    c5a = Clock.of(24, 0)
    c5b = Clock.of(48, 0)
    print("Test5:", str(c5a), "==", str(c5b), "->", c5a == c5b)  # Expected True