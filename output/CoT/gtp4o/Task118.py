# Chain-of-Through process in code generation:
# 1) Problem understanding:
#    Provide a function to validate IP addresses (IPv4/IPv6). Return "IPv4", "IPv6", or "Invalid".
# 2) Security requirements:
#    - Avoid unsafe regex and ambiguous parsing.
#    - Strict checks on characters, lengths, and counts to prevent logic flaws.
# 3) Secure coding generation:
#    - Manual parse both IPv4 and IPv6, trim outer whitespace, reject internal spaces.
# 4) Code review:
#    - Edge cases like leading zeros in IPv4, single/double colons in IPv6 handled.
# 5) Secure code output:
#    - Final validated functions and simple main tests.

def validate_ip_address(ip: str) -> str:
    if ip is None:
        return "Invalid"
    s = ip.strip()
    if not s:
        return "Invalid"
    if _is_valid_ipv4(s):
        return "IPv4"
    if _is_valid_ipv6(s):
        return "IPv6"
    return "Invalid"

def _is_valid_ipv4(s: str) -> bool:
    n = len(s)
    segments = 0
    num_digits = 0
    value = 0
    first_digit_zero = False

    for ch in s:
        if ch == '.':
            if num_digits == 0:
                return False
            segments += 1
            if segments > 3:
                return False
            if num_digits > 1 and first_digit_zero:
                return False
            if value > 255:
                return False
            num_digits = 0
            value = 0
            first_digit_zero = False
        elif '0' <= ch <= '9':
            if num_digits == 0:
                first_digit_zero = (ch == '0')
            if num_digits >= 3:
                return False
            value = value * 10 + (ord(ch) - ord('0'))
            num_digits += 1
            if value > 255:
                return False
        else:
            return False
    if num_digits == 0:
        return False
    if segments != 3:
        return False
    if num_digits > 1 and first_digit_zero:
        return False
    if value > 255:
        return False
    return True

def _is_hex(ch: str) -> bool:
    return ('0' <= ch <= '9') or ('a' <= ch <= 'f') or ('A' <= ch <= 'F')

def _parse_ipv6_segment(seg: str) -> int:
    # Returns number of groups in a segment without '::', or -1 if invalid
    if len(seg) == 0:
        return 0
    i = 0
    n = len(seg)
    count = 0
    while i < n:
        group_len = 0
        while i < n and _is_hex(seg[i]) and group_len < 4:
            i += 1
            group_len += 1
        if group_len == 0:
            return -1
        if i < n and _is_hex(seg[i]):
            return -1  # group too long (>4)
        count += 1
        if i == n:
            break
        if seg[i] != ':':
            return -1
        i += 1
        if i == n:
            return -1  # trailing colon -> empty group
    return count

def _is_valid_ipv6(s: str) -> bool:
    idx = s.find("::")
    if idx != -1:
        if s.find("::", idx + 1) != -1:
            return False
        left = s[:idx]
        right = s[idx + 2:]
        left_count = _parse_ipv6_segment(left)
        if left_count < 0:
            return False
        right_count = _parse_ipv6_segment(right)
        if right_count < 0:
            return False
        total = left_count + right_count
        if total > 7:
            return False
        missing = 8 - total
        if missing < 1:
            return False
        return True
    else:
        count = _parse_ipv6_segment(s)
        return count == 8

if __name__ == "__main__":
    tests = [
        "172.16.254.1",
        "2001:0db8:85a3:0000:0000:8A2E:0370:7334",
        "256.256.256.256",
        "2001:db8::8a2e:370:7334",
        "01.1.1.1"
    ]
    for t in tests:
        print(f"Input: {t} -> {validate_ip_address(t)}")