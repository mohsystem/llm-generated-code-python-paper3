import threading

class H2O:
    def __init__(self):
        self.hSlots = threading.Semaphore(2)
        self.oSlots = threading.Semaphore(1)

        self.mutex = threading.Semaphore(1)
        self.turnstile = threading.Semaphore(0)
        self.turnstile2 = threading.Semaphore(1)
        self.count = 0

    def barrier_phase1(self):
        leader = False
        self.mutex.acquire()
        self.count += 1
        if self.count == 3:
            self.turnstile2.acquire()
            for _ in range(3):
                self.turnstile.release()
            leader = True
        self.mutex.release()

        self.turnstile.acquire()
        self.turnstile.release()
        return leader

    def barrier_phase2(self):
        self.mutex.acquire()
        self.count -= 1
        if self.count == 0:
            self.turnstile.acquire()
            for _ in range(3):
                self.turnstile2.release()
        self.mutex.release()

        self.turnstile2.acquire()
        self.turnstile2.release()

    def hydrogen(self, releaseHydrogen):
        self.hSlots.acquire()
        leader = self.barrier_phase1()
        try:
            releaseHydrogen()
        finally:
            self.barrier_phase2()
            if leader:
                self.hSlots.release(2)
                self.oSlots.release(1)

    def oxygen(self, releaseOxygen):
        self.oSlots.acquire()
        leader = self.barrier_phase1()
        try:
            releaseOxygen()
        finally:
            self.barrier_phase2()
            if leader:
                self.hSlots.release(2)
                self.oSlots.release(1)

def make_water(water: str) -> str:
    out = []
    lock = threading.Lock()
    h2o = H2O()
    threads = []

    def relH():
        with lock:
            out.append('H')

    def relO():
        with lock:
            out.append('O')

    for c in water:
        if c == 'H':
            t = threading.Thread(target=lambda: h2o.hydrogen(relH))
        else:
            t = threading.Thread(target=lambda: h2o.oxygen(relO))
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return ''.join(out)

if __name__ == "__main__":
    tests = [
        "HOH",
        "OOHHHH",
        "HOHOHO",
        "HHOHHO",
        "OOOHHHHHH"
    ]
    for s in tests:
        res = make_water(s)
        print(f"Input: {s} -> Output: {res}")