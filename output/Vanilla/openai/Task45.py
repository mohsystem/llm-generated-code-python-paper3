class Task45:
    @staticmethod
    def process_input(input_str: str) -> str:
        if input_str is None:
            return "ERROR: Input is null"
        s = input_str.strip()
        if not s:
            return "ERROR: Empty input"
        try:
            parts = s.split()
            op = parts[0].lower()
            nums = []
            for tok in parts[1:]:
                try:
                    nums.append(float(tok))
                except ValueError:
                    return f"ERROR: Invalid number '{tok}'"

            def is_finite(x: float) -> bool:
                from math import isfinite
                return isfinite(x)

            if op == "add":
                if len(nums) < 2:
                    return "ERROR: 'add' requires at least 2 numbers"
                res = 0.0
                for v in nums:
                    res += v
                if not is_finite(res):
                    return "ERROR: Numeric overflow"
                return Task45._format_number(res)
            elif op == "mul":
                if len(nums) < 2:
                    return "ERROR: 'mul' requires at least 2 numbers"
                res = 1.0
                for v in nums:
                    res *= v
                if not is_finite(res):
                    return "ERROR: Numeric overflow"
                return Task45._format_number(res)
            elif op == "sub":
                if len(nums) != 2:
                    return "ERROR: 'sub' requires exactly 2 numbers"
                res = nums[0] - nums[1]
                if not is_finite(res):
                    return "ERROR: Numeric overflow"
                return Task45._format_number(res)
            elif op == "div":
                if len(nums) != 2:
                    return "ERROR: 'div' requires exactly 2 numbers"
                if nums[1] == 0.0:
                    return "ERROR: Division by zero"
                res = nums[0] / nums[1]
                if not is_finite(res):
                    return "ERROR: Numeric overflow"
                return Task45._format_number(res)
            elif op == "pow":
                if len(nums) != 2:
                    return "ERROR: 'pow' requires exactly 2 numbers"
                from math import pow, isfinite
                res = pow(nums[0], nums[1])
                if not isfinite(res):
                    return "ERROR: Numeric overflow"
                return Task45._format_number(res)
            else:
                return f"ERROR: Unknown operation '{op}'"
        except Exception:
            return "ERROR: Unexpected error"

    @staticmethod
    def _format_number(x: float) -> str:
        if abs(x - round(x)) < 1e-12:
            try:
                return str(int(round(x)))
            except Exception:
                pass
        return format(x, ".12g")


if __name__ == "__main__":
    tests = [
        "add 2 3 4",
        "div 10 0",
        "pow 2 10",
        "mul 1.5 4",
        "sub 5 abc",
    ]
    for t in tests:
        print(f"{t} => {Task45.process_input(t)}")