import re
from decimal import Decimal, getcontext

def process_input(user_input: str) -> str:
    if user_input is None:
        return "ERROR: input is null"
    if len(user_input) > 1000:
        return "ERROR: input too long"

    # Allowed characters validation
    if not re.fullmatch(r'[\s,\+\-\d]*', user_input):
        return "ERROR: invalid characters present"

    tokens = [t for t in re.split(r'[, \t\r\n]+', user_input.strip()) if t]
    if not tokens:
        return "ERROR: empty input"

    getcontext().prec = 28
    LL_MIN = -2**63
    LL_MAX = 2**63 - 1

    count = 0
    min_v = None
    max_v = None
    ssum = 0  # track as Python int but enforce 64-bit bounds on accumulation

    for tok in tokens:
        if count >= 100:
            return "ERROR: too many numbers (limit 100)"
        # Check numeric format and range
        if not re.fullmatch(r'[+\-]?\d{1,19}', tok):
            try:
                val = int(tok, 10)
            except ValueError:
                return f"ERROR: invalid number: {tok}"
        else:
            try:
                val = int(tok, 10)
            except ValueError:
                return f"ERROR: invalid number: {tok}"

        if val < LL_MIN or val > LL_MAX:
            return f"ERROR: number out of range: {tok}"

        # sum with 64-bit overflow check
        if val > 0 and ssum > LL_MAX - val:
            return "ERROR: sum overflow"
        if val < 0 and ssum < LL_MIN - val:
            return "ERROR: sum overflow"
        ssum += val

        min_v = val if min_v is None else min(min_v, val)
        max_v = val if max_v is None else max(max_v, val)
        count += 1

    if count == 0:
        return "ERROR: no numbers found"

    avg = Decimal(ssum) / Decimal(count)
    # Normalize representation (strip trailing zeros)
    avg_str = format(avg.normalize(), 'f').rstrip('0').rstrip('.') if '.' in format(avg, 'f') else format(avg, 'f')

    return f"OK: count={count}, sum={ssum}, min={min_v}, max={max_v}, average={avg_str}"

if __name__ == "__main__":
    tests = [
        "1, 2, 3, 4, 5",
        " 10 20 30 ",
        "-5, -10, 15",
        "abc",
        "9223372036854775807, 1"
    ]
    for t in tests:
        print(f'Input: "{t}" -> {process_input(t)}')