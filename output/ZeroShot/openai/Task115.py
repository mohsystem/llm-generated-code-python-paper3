class BitFlags:
    __slots__ = ("read", "write", "execute", "role", "priority")

    def __init__(self, read: int, write: int, execute: int, role: int, priority: int):
        self.read = read
        self.write = write
        self.execute = execute
        self.role = role
        self.priority = priority

    @staticmethod
    def _validate_bit(v: int, name: str) -> None:
        if v not in (0, 1):
            raise ValueError(f"Invalid {name} bit: {v}")

    @staticmethod
    def _validate_range(v: int, minv: int, maxv: int, name: str) -> None:
        if v < minv or v > maxv:
            raise ValueError(f"Invalid {name}: {v}")

    @staticmethod
    def build_packed(read: int, write: int, execute: int, role: int, priority: int) -> int:
        BitFlags._validate_bit(read, "read")
        BitFlags._validate_bit(write, "write")
        BitFlags._validate_bit(execute, "execute")
        BitFlags._validate_range(role, 0, 3, "role")
        BitFlags._validate_range(priority, 0, 15, "priority")
        p = 0
        p |= (read & 1) << 0
        p |= (write & 1) << 1
        p |= (execute & 1) << 2
        p |= (role & 0b11) << 3
        p |= (priority & 0xF) << 5
        return p

    @staticmethod
    def from_packed(packed: int) -> "BitFlags":
        if not isinstance(packed, int) or packed < 0:
            raise ValueError("packed must be a non-negative integer")
        read = (packed >> 0) & 1
        write = (packed >> 1) & 1
        execute = (packed >> 2) & 1
        role = (packed >> 3) & 0b11
        priority = (packed >> 5) & 0xF
        return BitFlags(read, write, execute, role, priority)

    def __repr__(self) -> str:
        return f"BitFlags(read={self.read}, write={self.write}, execute={self.execute}, role={self.role}, priority={self.priority})"


def build_packed(read: int, write: int, execute: int, role: int, priority: int) -> int:
    return BitFlags.build_packed(read, write, execute, role, priority)


def unpack(packed: int):
    bf = BitFlags.from_packed(packed)
    return {
        "read": bf.read,
        "write": bf.write,
        "execute": bf.execute,
        "role": bf.role,
        "priority": bf.priority,
    }


if __name__ == "__main__":
    tests = [
        (1, 1, 0, 2, 7),
        (0, 0, 1, 1, 0),
        (1, 0, 1, 3, 15),
        (1, 1, 1, 4, 2),   # invalid role
        (1, 0, 0, 0, 16),  # invalid priority
    ]
    for i, t in enumerate(tests, 1):
        try:
            packed = build_packed(*t)
            print(f"Test {i}: packed={packed} unpacked={unpack(packed)}")
        except Exception as e:
            print(f"Test {i}: error={e}")