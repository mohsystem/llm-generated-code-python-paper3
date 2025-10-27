import sys

def add_thousand(x: int) -> int:
    if not isinstance(x, int) or isinstance(x, bool):
        raise TypeError("Input must be an integer.")
    return x + 1000

if __name__ == "__main__":
    if len(sys.argv) > 1:
        s = (sys.argv[1] or "").strip()
        try:
            # Only decimal input; adjust base if needed
            n = int(s, 10)
            print(add_thousand(n))
        except ValueError:
            print("Error: Input must be a valid integer.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # 5 test cases
        tests = [
            0,
            1,
            -1000,
            (2**63 - 1) - 1000,
            (2**63 - 1),
        ]
        for t in tests:
            try:
                r = add_thousand(t)
                print(f"add_thousand({t}) = {r}")
            except Exception as e:
                print(f"add_thousand({t}) = error: {e}")