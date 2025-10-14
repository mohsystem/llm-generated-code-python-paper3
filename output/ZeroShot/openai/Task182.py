class Task182:
    @staticmethod
    def clean_number(s: str) -> str:
        if s is None:
            return ""
        digits = "".join(ch for ch in s if ch.isdigit())
        if len(digits) == 11:
            if digits[0] != "1":
                return ""
            digits = digits[1:]
        if len(digits) != 10:
            return ""
        if digits[0] < "2" or digits[0] > "9":
            return ""
        if digits[3] < "2" or digits[3] > "9":
            return ""
        return digits

if __name__ == "__main__":
    tests = [
        "+1 (613)-995-0253",
        "613-995-0253",
        "1 613 995 0253",
        "613.995.0253",
        "123-456-7890"  # invalid
    ]
    for t in tests:
        print(Task182.clean_number(t))