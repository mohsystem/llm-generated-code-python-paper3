class Clock:
    def __init__(self, minutes_total: int):
        self._minutes = self._normalize(minutes_total)

    @staticmethod
    def _normalize(total_minutes: int) -> int:
        m = total_minutes % (24 * 60)
        return m

    @staticmethod
    def at(hour: int, minute: int):
        return Clock(hour * 60 + minute)

    def add(self, minutes: int):
        return Clock(self._minutes + minutes)

    def subtract(self, minutes: int):
        return Clock(self._minutes - minutes)

    @property
    def hour(self) -> int:
        return self._minutes // 60

    @property
    def minute(self) -> int:
        return self._minutes % 60

    def __str__(self) -> str:
        return f"{self.hour:02d}:{self.minute:02d}"

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other) -> bool:
        if not isinstance(other, Clock):
            return NotImplemented
        return self._minutes == other._minutes

    def __hash__(self) -> int:
        return hash(self._minutes)


# Example helper function that takes parameters and returns output string
def clock_after_adding(h: int, m: int, delta: int) -> str:
    return str(Clock.at(h, m).add(delta))


if __name__ == "__main__":
    # 5 test cases
    c1 = Clock.at(10, 0).add(3)
    print("Test1", c1)  # 10:03

    c2 = Clock.at(23, 30).add(90)
    print("Test2", c2)  # 01:00

    c3 = Clock.at(0, 10).subtract(20)
    print("Test3", c3)  # 23:50

    c4a = Clock.at(15, 37)
    c4b = Clock.at(14, 97)  # same as 15:37
    print("Test4 equals", c4a == c4b)  # True

    c5a = Clock.at(5, 32)
    c5b = c5a.add(24 * 60)  # wrap full day
    print("Test5 equals", c5a == c5b, c5b)  # True 05:32