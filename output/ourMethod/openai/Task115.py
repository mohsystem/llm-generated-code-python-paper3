from dataclasses import dataclass
from typing import Tuple, List

# Bit positions and masks for a 16-bit status register:
# [bit0=isActive][bit1=isError][bits2-4=priority(3)][bits5-8=level(4)][bits9-15=code(7)]
ACTIVE_SHIFT = 0
ERROR_SHIFT = 1
PRIORITY_SHIFT = 2
LEVEL_SHIFT = 5
CODE_SHIFT = 9

ACTIVE_MASK = 0x1 << ACTIVE_SHIFT
ERROR_MASK = 0x1 << ERROR_SHIFT
PRIORITY_MASK = 0x7 << PRIORITY_SHIFT
LEVEL_MASK = 0xF << LEVEL_SHIFT
CODE_MASK = 0x7F << CODE_SHIFT

MAX_PRIORITY = 7
MAX_LEVEL = 15
MAX_CODE = 127

@dataclass(frozen=True)
class Status:
    is_active: bool
    is_error: bool
    priority: int
    level: int
    code: int

def _validate_range(name: str, value: int, min_v: int, max_v: int) -> None:
    if not isinstance(value, int):
        raise ValueError(f"{name} must be int")
    if value < min_v or value > max_v:
        raise ValueError(f"Invalid {name} value: {value} (allowed {min_v}-{max_v})")

def pack(is_active: bool, is_error: bool, priority: int, level: int, code: int) -> int:
    if not isinstance(is_active, bool) or not isinstance(is_error, bool):
        raise ValueError("is_active and is_error must be bool")
    _validate_range("priority", priority, 0, MAX_PRIORITY)
    _validate_range("level", level, 0, MAX_LEVEL)
    _validate_range("code", code, 0, MAX_CODE)
    v = 0
    v |= (1 if is_active else 0) << ACTIVE_SHIFT
    v |= (1 if is_error else 0) << ERROR_SHIFT
    v |= (priority & 0x7) << PRIORITY_SHIFT
    v |= (level & 0xF) << LEVEL_SHIFT
    v |= (code & 0x7F) << CODE_SHIFT
    return v & 0xFFFF

def unpack(packed: int) -> Status:
    _validate_range("packed", packed, 0, 0xFFFF)
    is_active = ((packed & ACTIVE_MASK) >> ACTIVE_SHIFT) == 1
    is_error = ((packed & ERROR_MASK) >> ERROR_SHIFT) == 1
    priority = (packed & PRIORITY_MASK) >> PRIORITY_SHIFT
    level = (packed & LEVEL_MASK) >> LEVEL_SHIFT
    code = (packed & CODE_MASK) >> CODE_SHIFT
    return Status(is_active=is_active, is_error=is_error, priority=priority, level=level, code=code)

def main() -> None:
    tests: List[Tuple[bool, bool, int, int, int]] = [
        (True, False, 3, 8, 42),
        (False, True, 7, 15, 127),
        (True, True, 0, 0, 0),
        (False, False, 5, 9, 100),
        (True, False, 9, 2, 5),  # invalid priority
    ]
    for i, t in enumerate(tests, 1):
        print("Test", i, "input:", t)
        try:
            packed = pack(*t)
            print("Packed:", packed)
            s = unpack(packed)
            print("Unpacked:", s)
        except ValueError as e:
            print("Error:", str(e))

if __name__ == "__main__":
    main()