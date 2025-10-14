import secrets
import string

class RobotFactory:
    _allocated = set()
    _CAPACITY = 26 * 26 * 1000

    @classmethod
    def generate_unique(cls):
        if len(cls._allocated) >= cls._CAPACITY:
            raise RuntimeError("All possible robot names have been allocated.")
        while True:
            letters = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(2))
            num = secrets.randbelow(1000)
            name = f"{letters}{num:03d}"
            if name not in cls._allocated:
                cls._allocated.add(name)
                return name

    @classmethod
    def release(cls, name: str):
        cls._allocated.discard(name)


class Robot:
    def __init__(self):
        self._name = None

    def get_name(self) -> str:
        if self._name is None:
            self._name = RobotFactory.generate_unique()
        return self._name

    def reset(self):
        if self._name is not None:
            RobotFactory.release(self._name)
            self._name = None


def main():
    r1 = Robot()
    r2 = Robot()
    r3 = Robot()
    print("R1:", r1.get_name())
    print("R2:", r2.get_name())
    print("R3:", r3.get_name())
    r4 = Robot()
    print("R4:", r4.get_name())
    r2.reset()
    print("R2 after reset:", r2.get_name())


if __name__ == "__main__":
    main()