class Clock:
    __slots__ = ("_minutes",)

    def __init__(self, hour: int, minute: int = 0):
        total = hour * 60 + minute
        self._minutes = total % (24 * 60)

    def add(self, minutes: int) -> "Clock":
        total = (self._minutes + minutes) % (24 * 60)
        return Clock(0, total)

    def subtract(self, minutes: int) -> "Clock":
        return self.add(-minutes)

    @property
    def hour(self) -> int:
        return self._minutes // 60

    @property
    def minute(self) -> int:
        return self._minutes % 60

    def __eq__(self, other) -> bool:
        if not isinstance(other, Clock):
            return False
        return self._minutes == other._minutes

    def __str__(self) -> str:
        return f"{self.hour:02d}:{self.minute:02d}"

# Example API functions that accept inputs and return outputs
def create_clock(hour: int, minute: int) -> Clock:
    return Clock(hour, minute)

def add_minutes(clock: Clock, minutes: int) -> Clock:
    return clock.add(minutes)

def subtract_minutes(clock: Clock, minutes: int) -> Clock:
    return clock.subtract(minutes)

def clocks_equal(a: Clock, b: Clock) -> bool:
    return a == b

def clock_to_string(c: Clock) -> str:
    return str(c)

if __name__ == "__main__":
    # 5 test cases
    t1 = add_minutes(create_clock(10, 0), 3)
    print("Test1:", clock_to_string(t1))  # 10:03

    t2 = add_minutes(create_clock(23, 59), 2)
    print("Test2:", clock_to_string(t2))  # 00:01

    t3 = subtract_minutes(create_clock(0, 3), 4)
    print("Test3:", clock_to_string(t3))  # 23:59

    t4a = create_clock(25, 0)
    t4b = create_clock(1, 0)
    print("Test4: equal=", clocks_equal(t4a, t4b))  # True

    t5 = add_minutes(create_clock(2, 30), -1500)  # -25 hours
    print("Test5:", clock_to_string(t5), "equal 01:30?", clocks_equal(t5, create_clock(1, 30)))  # 01:30 True