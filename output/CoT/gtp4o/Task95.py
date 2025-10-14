# Chain-of-Through Step 1: Problem understanding
# - Implement function returning current processor time in seconds and demonstrate 5 test cases.
#
# Chain-of-Through Step 2: Security requirements
# - No external inputs; rely on standard library safely.
#
# Chain-of-Through Step 3: Secure coding generation
# - Use time.process_time() which returns CPU time in seconds.
#
# Chain-of-Through Step 4: Code review
# - No risky operations; straightforward computation.
#
# Chain-of-Through Step 5: Secure code output
# - Final code below.

import time
import math

def get_processor_time_seconds():
    return time.process_time()

def burn_cpu(iterations):
    x = 0.0
    for i in range(1, iterations + 1):
        x += math.sqrt((i % 1000) + 1.0)
    return x  # return to avoid being optimized away by interpreters/JITs

if __name__ == "__main__":
    for t in range(1, 6):
        burn_cpu(200000 * t)
        seconds = get_processor_time_seconds()
        print(f"Python Test {t} - CPU Time (s): {seconds:.9f}")