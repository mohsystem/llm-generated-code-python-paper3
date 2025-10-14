class Task118:
    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        if ip is None:
            return False
        ip = ip.strip()
        if not ip or ip[0] == '.' or ip[-1] == '.':
            return False
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for p in parts:
            if len(p) == 0 or len(p) > 3:
                return False
            if not p.isdigit():
                return False
            if len(p) > 1 and p[0] == '0':
                return False
            val = int(p)
            if val < 0 or val > 255:
                return False
        return True

    @staticmethod
    def _is_hex_group(s: str) -> bool:
        if len(s) < 1 or len(s) > 4:
            return False
        for c in s:
            if not (c.isdigit() or 'a' <= c.lower() <= 'f'):
                return False
        return True

    @staticmethod
    def is_valid_ipv6(ip: str) -> bool:
        if ip is None:
            return False
        ip = ip.strip()
        if not ip:
            return False
        if '.' in ip:
            return False  # no embedded IPv4 support here
        if '::' in ip:
            if ip.count('::') > 1:
                return False
            left, right = ip.split('::', 1)
            left_parts = [] if left == '' else left.split(':')
            right_parts = [] if right == '' else right.split(':')
            # No empty parts allowed on either side
            if any(len(p) == 0 or not Task118._is_hex_group(p) for p in left_parts):
                return False
            if any(len(p) == 0 or not Task118._is_hex_group(p) for p in right_parts):
                return False
            groups = len(left_parts) + len(right_parts)
            if groups > 7:
                return False
            return True
        else:
            parts = ip.split(':')
            if len(parts) != 8:
                return False
            return all(Task118._is_hex_group(p) for p in parts)

    @staticmethod
    def validate_ip_address(ip: str) -> str:
        if Task118.is_valid_ipv4(ip):
            return "IPv4"
        if Task118.is_valid_ipv6(ip):
            return "IPv6"
        return "Neither"

    @staticmethod
    def normalize_ipv4(ip: str) -> str | None:
        if not Task118.is_valid_ipv4(ip):
            return None
        parts = ip.strip().split('.')
        return '.'.join(str(int(p)) for p in parts)

    @staticmethod
    def _pad4_upper(h: str) -> str:
        h = h.upper()
        return ('0' * (4 - len(h))) + h

    @staticmethod
    def normalize_ipv6(ip: str) -> str | None:
        if not Task118.is_valid_ipv6(ip):
            return None
        ip = ip.strip()
        groups: list[str] = []
        if '::' in ip:
            left, right = ip.split('::', 1)
            left_parts = [] if left == '' else left.split(':')
            right_parts = [] if right == '' else right.split(':')
            groups.extend(left_parts)
            zeros_to_insert = 8 - (len(left_parts) + len(right_parts))
            groups.extend(['0'] * zeros_to_insert)
            groups.extend(right_parts)
        else:
            groups = ip.split(':')
        if len(groups) != 8:
            return None
        return ':'.join(Task118._pad4_upper(g) for g in groups)

if __name__ == "__main__":
    tests = [
        "172.16.254.1",
        "2001:0db8:85a3:0000:0000:8A2E:0370:7334",
        "2001:db8:85a3::8a2e:370:7334",
        "256.256.256.256",
        "01.1.1.1",
    ]
    for ip in tests:
        kind = Task118.validate_ip_address(ip)
        print(f"IP: {ip} -> {kind}")
        if kind == "IPv4":
            print("Normalized IPv4:", Task118.normalize_ipv4(ip))
        elif kind == "IPv6":
            print("Normalized IPv6:", Task118.normalize_ipv6(ip))
        print()