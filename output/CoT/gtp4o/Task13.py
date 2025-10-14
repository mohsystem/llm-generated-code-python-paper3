# Chain-of-Through process in code generation:
# 1) Problem understanding: Validate a walk of directions; must be 10 steps and return to origin.
# 2) Security requirements: Validate inputs (type, length, allowed chars) and avoid side effects.
# 3) Secure coding generation: Defensive programming against unexpected inputs.
# 4) Code review: Ensure robustness against invalid values.
# 5) Secure code output: Final safe implementation with tests.

from typing import List

def is_valid_walk(walk: List[str]) -> bool:
    if walk is None or len(walk) != 10:
        return False
    x = 0
    y = 0
    for step in walk:
        if not isinstance(step, str) or len(step) != 1:
            return False
        if step == 'n':
            y += 1
        elif step == 's':
            y -= 1
        elif step == 'e':
            x += 1
        elif step == 'w':
            x -= 1
        else:
            return False
    return x == 0 and y == 0

if __name__ == "__main__":
    # 5 test cases
    tests = [
        ['n','s','n','s','n','s','n','s','n','s'],         # True
        ['w','e','w','e','w'],                             # False
        ['n','n','n','s','n','s','n','s','n','s'],         # False
        ['e','w','e','w','e','w','e','w','e','w'],         # True
        ['n','n','n','n','n','s','s','s','s','e'],         # False
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {is_valid_walk(t)}")