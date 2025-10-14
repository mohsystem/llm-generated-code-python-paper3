class Task118:
    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        if ip is None or len(ip) == 0:
            return False
        n = len(ip)
        seg = 0
        i = 0
        while i < n:
            if seg == 4:
                return False
            if i >= n or not ip[i].isdigit():
                return False
            # Leading zero rule
            if ip[i] == '0':
                i += 1
                if i < n and ip[i].isdigit():
                    return False
            else:
                val = 0
                len_part = 0
                while i < n and ip[i].isdigit():
                    if len_part >= 3:
                        return False
                    val = val * 10 + (ord(ip[i]) - ord('0'))
                    if val > 255:
                        return False
                    len_part += 1
                    i += 1
                if len_part == 0:
                    return False
            seg += 1
            if seg < 4:
                if i >= n or ip[i] != '.':
                    return False
                i += 1
                if i >= n:
                    return False
            else:
                if i != n:
                    return False
        return seg == 4

    @staticmethod
    def _is_hex_group(s: str) -> bool:
        if not (1 <= len(s) <= 4):
            return False
        for ch in s:
            if not (ch.isdigit() or ('a' <= ch.lower() <= 'f')):
                return False
        return True

    @staticmethod
    def is_valid_ipv6(ip: str) -> bool:
        if ip is None or len(ip) == 0:
            return False
        if '.' in ip:
            return False  # not supporting embedded IPv4
        idx = ip.find("::")
        if idx != -1:
            if ip.find("::", idx + 2) != -1:
                return False
            left = ip[:idx]
            right = ip[idx + 2:]
            left_count = 0
            if left:
                lparts = left.split(":")
                for p in lparts:
                    if p == "" or not Task118._is_hex_group(p):
                        return False
                    left_count += 1
            right_count = 0
            if right:
                rparts = right.split(":")
                for p in rparts:
                    if p == "" or not Task118._is_hex_group(p):
                        return False
                    right_count += 1
            return (left_count + right_count) < 8
        else:
            parts = ip.split(":")
            if len(parts) != 8:
                return False
            for p in parts:
                if p == "" or not Task118._is_hex_group(p):
                    return False
            return True

    @staticmethod
    def classify_ip(ip: str) -> str:
        if Task118.is_valid_ipv4(ip):
            return "IPv4"
        if Task118.is_valid_ipv6(ip):
            return "IPv6"
        return "Invalid"


if __name__ == "__main__":
    tests = [
        "192.168.1.1",
        "255.256.0.1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8::1",
        "01.1.1.1",
    ]
    for t in tests:
        print(f"{t} => {Task118.classify_ip(t)}")