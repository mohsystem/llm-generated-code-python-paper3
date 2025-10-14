# Task188 - Python implementation
# Chain-of-Through process:
# 1) Problem understanding: produce "foobar" n times with two threads alternating.
# 2) Security requirements: bound n, avoid deadlocks, use safe synchronization primitives.
# 3) Secure coding generation: use Semaphores to alternate; controlled shared list to collect output.
# 4) Code review: no busy wait, threads joined, proper resource handling.
# 5) Secure code output: clamp n to [0,1000].

import threading

def solve(n: int) -> str:
    if n < 0:
        n = 0
    if n > 1000:
        n = 1000

    sfoo = threading.Semaphore(1)
    sbar = threading.Semaphore(0)
    res = []

    def foo():
        for _ in range(n):
            sfoo.acquire()
            res.append("foo")
            sbar.release()

    def bar():
        for _ in range(n):
            sbar.acquire()
            res.append("bar")
            sfoo.release()

    t1 = threading.Thread(target=foo, name="foo-thread", daemon=False)
    t2 = threading.Thread(target=bar, name="bar-thread", daemon=False)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    return "".join(res)

if __name__ == "__main__":
    tests = [1, 2, 3, 5, 7]
    for n in tests:
        print(solve(n))