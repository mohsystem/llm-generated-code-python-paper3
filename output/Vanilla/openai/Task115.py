class Task115:
    class Packet:
        def __init__(self, version: int, type_: int, flags: int, length: int, checksum: int):
            self.version = version & 0x7      # 3 bits
            self.type = type_ & 0x1F         # 5 bits
            self.flags = flags & 0xF         # 4 bits
            self.length = length & 0xFFF     # 12 bits
            self.checksum = checksum & 0xFF  # 8 bits

        def __repr__(self):
            return f"Packet(version={self.version}, type={self.type}, flags={self.flags}, length={self.length}, checksum={self.checksum})"

    @staticmethod
    def pack_packet(version: int, type_: int, flags: int, length: int, checksum: int) -> int:
        v = version & 0x7
        t = type_ & 0x1F
        f = flags & 0xF
        l = length & 0xFFF
        c = checksum & 0xFF
        return (c << 24) | (l << 12) | (f << 8) | (t << 3) | v

    @staticmethod
    def unpack_packet(value: int) -> "Task115.Packet":
        v = value & 0x7
        t = (value >> 3) & 0x1F
        f = (value >> 8) & 0xF
        l = (value >> 12) & 0xFFF
        c = (value >> 24) & 0xFF
        return Task115.Packet(v, t, f, l, c)


if __name__ == "__main__":
    tests = [
        (1, 3, 2, 100, 200),
        (7, 31, 15, 4095, 255),
        (0, 0, 0, 0, 0),
        (5, 10, 8, 2048, 128),
        (2, 18, 7, 1234, 77),
    ]
    for t in tests:
        packed = Task115.pack_packet(*t)
        unpacked = Task115.unpack_packet(packed)
        print(f"Input  : {t}")
        print(f"Packed : 0x{packed:08X}")
        print(f"Unpack : {unpacked}")
        print("---")