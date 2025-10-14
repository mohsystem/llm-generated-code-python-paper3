from __future__ import annotations

class Clock:
    __slots__ = ("_hour", "_minute")

    def __init__(self, hours: int, minutes: int) -> None:
        h, m = Clock._normalize(hours, minutes)
        self._hour = h
        self._minute = m

    @staticmethod
    def _normalize(hours: int, minutes: int) -> tuple[int, int]:
        total = hours * 60 + minutes
        mod = total % 1440
        return (mod // 60, mod % 60)

    def add_minutes(self, delta: int) -> Clock:
        return Clock(self._hour, self._minute + delta)

    def subtract_minutes(self, delta: int) -> Clock:
        return Clock(self._hour, self._minute - delta)

    def hour(self) -> int:
        return self._hour

    def minute(self) -> int:
        return self._minute

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Clock):
            return False
        return self._hour == other._hour and self._minute == other._minute

    def __str__(self) -> str:
        return f"{self._hour:02d}:{self._minute:02d}"


def main() -> None:
    # Test case 1: 10:00 + 3 minutes = 10:03
    t1 = Clock(10, 0).add_minutes(3)
    print("Test1", str(t1))

    # Test case 2: 10:00 + 61 minutes = 11:01
    t2 = Clock(10, 0).add_minutes(61)
    print("Test2", str(t2))

    # Test case 3: 23:59 + 2 minutes = 00:01
    t3 = Clock(23, 59).add_minutes(2)
    print("Test3", str(t3))

    # Test case 4: 00:30 - 90 minutes = 23:00
    t4 = Clock(0, 30).subtract_minutes(90)
    print("Test4", str(t4))

    # Test case 5: equality: 25:00 == 01:00
    a = Clock(25, 0)
    b = Clock(1, 0)
    print("Test5", f"{a} == {b} -> {a == b}")


if __name__ == "__main__":
    main()