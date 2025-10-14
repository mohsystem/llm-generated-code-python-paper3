
from typing import Optional

class Clock:
    _MINUTES_PER_HOUR: int = 60
    _HOURS_PER_DAY: int = 24
    _MINUTES_PER_DAY: int = _MINUTES_PER_HOUR * _HOURS_PER_DAY

    def __init__(self, hours: int, minutes: int) -> None:
        if not isinstance(hours, int) or not isinstance(minutes, int):
            raise TypeError("Hours and minutes must be integers")
        if hours < 0 or hours > 23:
            raise ValueError("Hours must be between 0 and 23")
        if minutes < 0 or minutes > 59:
            raise ValueError("Minutes must be between 0 and 59")
        self._minutes: int = (hours * self._MINUTES_PER_HOUR + minutes) % self._MINUTES_PER_DAY

    @classmethod
    def _from_total_minutes(cls, total_minutes: int) -> 'Clock':
        if not isinstance(total_minutes, int):
            raise TypeError("Total minutes must be an integer")
        if total_minutes < -(10**9) or total_minutes > 10**9:
            raise ValueError("Total minutes out of safe range")
        instance = cls.__new__(cls)
        instance._minutes = ((total_minutes % cls._MINUTES_PER_DAY) + cls._MINUTES_PER_DAY) % cls._MINUTES_PER_DAY
        return instance

    def add_minutes(self, minutes_to_add: int) -> 'Clock':
        if not isinstance(minutes_to_add, int):
            raise TypeError("Minutes to add must be an integer")
        if minutes_to_add < -(10**9) or minutes_to_add > 10**9:
            raise ValueError("Minutes to add out of safe range")
        return Clock._from_total_minutes(self._minutes + minutes_to_add)

    def subtract_minutes(self, minutes_to_subtract: int) -> 'Clock':
        if not isinstance(minutes_to_subtract, int):
            raise TypeError("Minutes to subtract must be an integer")
        if minutes_to_subtract < -(10**9) or minutes_to_subtract > 10**9:
            raise ValueError("Minutes to subtract out of safe range")
        return Clock._from_total_minutes(self._minutes - minutes_to_subtract)

    def get_hours(self) -> int:
        return self._minutes // self._MINUTES_PER_HOUR

    def get_minutes(self) -> int:
        return self._minutes % self._MINUTES_PER_HOUR

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Clock):
            return False
        return self._minutes == other._minutes

    def __hash__(self) -> int:
        return hash(self._minutes)

    def __str__(self) -> str:
        return f"{self.get_hours():02d}:{self.get_minutes():02d}"


def main() -> None:
    # Test case 1: Basic clock creation
    clock1 = Clock(10, 30)
    print(f"Test 1 - Clock created: {clock1}")

    # Test case 2: Add minutes
    clock2 = clock1.add_minutes(45)
    print(f"Test 2 - Add 45 minutes to 10:30: {clock2}")

    # Test case 3: Subtract minutes
    clock3 = Clock(12, 15)
    clock4 = clock3.subtract_minutes(30)
    print(f"Test 3 - Subtract 30 minutes from 12:15: {clock4}")

    # Test case 4: Equality check
    clock5 = Clock(8, 20)
    clock6 = Clock(8, 20)
    print(f"Test 4 - Clocks equal (8:20 == 8:20): {clock5 == clock6}")

    # Test case 5: Wrap around midnight
    clock7 = Clock(23, 45)
    clock8 = clock7.add_minutes(30)
    print(f"Test 5 - Add 30 minutes to 23:45 (wrap around): {clock8}")


if __name__ == "__main__":
    main()
