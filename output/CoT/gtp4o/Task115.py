# Chain-of-Through secure code generation process embedded as comments.
# 1) Problem understanding: Simulate bit fields in Python using an integer with masking/shifting.
#    Fields: read(1), write(1), execute(1), role(2), level(5) packed into lower 10 bits.
# 2) Security requirements: Validate ranges, avoid negative shifts, constrain to 16-bit.
# 3) Secure coding generation: Class encapsulates state, factory methods validate.
# 4) Code review: All masks applied; no external input parsing.
# 5) Secure code output: Final, safe conversion and accessors.

from typing import Tuple

class BitPermissions:
    READ_SHIFT = 0
    WRITE_SHIFT = 1
    EXEC_SHIFT = 2
    ROLE_SHIFT = 3
    LEVEL_SHIFT = 5

    READ_MASK = 0x1
    WRITE_MASK = 0x1
    EXEC_MASK = 0x1
    ROLE_MASK = 0x3
    LEVEL_MASK = 0x1F

    __slots__ = ("_packed",)

    def __init__(self, packed: int) -> None:
        self._packed = packed & 0xFFFF

    @classmethod
    def from_fields(cls, read: int, write: int, execute: int, role: int, level: int) -> "BitPermissions":
        if read & ~cls.READ_MASK: raise ValueError("read out of range")
        if write & ~cls.WRITE_MASK: raise ValueError("write out of range")
        if execute & ~cls.EXEC_MASK: raise ValueError("execute out of range")
        if role & ~cls.ROLE_MASK: raise ValueError("role out of range")
        if level & ~cls.LEVEL_MASK: raise ValueError("level out of range")
        p = 0
        p |= (read   & cls.READ_MASK)  << cls.READ_SHIFT
        p |= (write  & cls.WRITE_MASK) << cls.WRITE_SHIFT
        p |= (execute& cls.EXEC_MASK)  << cls.EXEC_SHIFT
        p |= (role   & cls.ROLE_MASK)  << cls.ROLE_SHIFT
        p |= (level  & cls.LEVEL_MASK) << cls.LEVEL_SHIFT
        return cls(p)

    @classmethod
    def from_packed(cls, packed: int) -> "BitPermissions":
        return cls(packed & 0xFFFF)

    def to_packed(self) -> int:
        return self._packed & 0xFFFF

    def get_read(self) -> int:
        return (self._packed >> self.READ_SHIFT) & self.READ_MASK

    def get_write(self) -> int:
        return (self._packed >> self.WRITE_SHIFT) & self.WRITE_MASK

    def get_execute(self) -> int:
        return (self._packed >> self.EXEC_SHIFT) & self.EXEC_MASK

    def get_role(self) -> int:
        return (self._packed >> self.ROLE_SHIFT) & self.ROLE_MASK

    def get_level(self) -> int:
        return (self._packed >> self.LEVEL_SHIFT) & self.LEVEL_MASK

    def __repr__(self) -> str:
        return (
            f"BitPermissions(read={self.get_read()}, write={self.get_write()}, "
            f"execute={self.get_execute()}, role={self.get_role()}, level={self.get_level()}, "
            f"packed=0x{self._packed:04X})"
        )

def pack_permissions(read: int, write: int, execute: int, role: int, level: int) -> int:
    return BitPermissions.from_fields(read, write, execute, role, level).to_packed()

def unpack_permissions(packed: int) -> Tuple[int, int, int, int, int]:
    bp = BitPermissions.from_packed(packed)
    return (bp.get_read(), bp.get_write(), bp.get_execute(), bp.get_role(), bp.get_level())

def main():
    tests = [
        (1,0,1,2,17),
        (0,1,1,1,31),
        (1,1,1,3,0),
        (0,0,0,0,5),
        (1,1,0,2,29),
    ]
    for i, t in enumerate(tests, 1):
        bp = BitPermissions.from_fields(*t)
        print(f"Test {i} -> {bp!r}")
        packed = pack_permissions(*t)
        ur, uw, ue, uro, ul = unpack_permissions(packed)
        print(f"Unpacked {i} -> read={ur}, write={uw}, execute={ue}, role={uro}, level={ul}, packed=0x{packed:04X}")

if __name__ == "__main__":
    main()