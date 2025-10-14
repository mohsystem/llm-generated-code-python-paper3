
import secrets
from typing import Optional, Set

class Robot:
    _used_names: Set[str] = set()
    _MAX_ATTEMPTS: int = 10000
    
    def __init__(self) -> None:
        self._name: Optional[str] = None
    
    def get_name(self) -> str:
        if self._name is None:
            self._name = self._generate_unique_name()
        return self._name
    
    def reset(self) -> None:
        if self._name is not None:
            Robot._used_names.discard(self._name)
            self._name = None
    
    @classmethod
    def _generate_unique_name(cls) -> str:
        for _ in range(cls._MAX_ATTEMPTS):
            candidate = cls._generate_random_name()
            if candidate not in cls._used_names:
                cls._used_names.add(candidate)
                return candidate
        raise RuntimeError(f"Failed to generate unique name after {cls._MAX_ATTEMPTS} attempts")
    
    @staticmethod
    def _generate_random_name() -> str:
        letter1 = chr(ord('A') + secrets.randbelow(26))
        letter2 = chr(ord('A') + secrets.randbelow(26))
        digit1 = secrets.randbelow(10)
        digit2 = secrets.randbelow(10)
        digit3 = secrets.randbelow(10)
        return f"{letter1}{letter2}{digit1}{digit2}{digit3}"


def main() -> None:
    robot1 = Robot()
    print(f"Robot 1 name: {robot1.get_name()}")
    print(f"Robot 1 name again: {robot1.get_name()}")
    
    robot2 = Robot()
    print(f"Robot 2 name: {robot2.get_name()}")
    
    robot1.reset()
    print(f"Robot 1 after reset: {robot1.get_name()}")
    
    robot3 = Robot()
    print(f"Robot 3 name: {robot3.get_name()}")
    
    robot2.reset()
    print(f"Robot 2 after reset: {robot2.get_name()}")


if __name__ == "__main__":
    main()
