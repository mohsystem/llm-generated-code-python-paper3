import threading

def solve(n: int) -> str:
    sb = []
    semFoo = threading.Semaphore(1)
    semBar = threading.Semaphore(0)

    def foo():
        for _ in range(n):
            semFoo.acquire()
            sb.append("foo")
            semBar.release()

    def bar():
        for _ in range(n):
            semBar.acquire()
            sb.append("bar")
            semFoo.release()

    t1 = threading.Thread(target=foo)
    t2 = threading.Thread(target=bar)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    return "".join(sb)

if __name__ == "__main__":
    for n in [1, 2, 3, 4, 5]:
        print(solve(n))