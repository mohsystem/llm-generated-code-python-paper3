import threading

class BankAccount:
    def __init__(self):
        self._lock = threading.Lock()
        self._open = False
        self._balance = 0

    def open(self):
        with self._lock:
            if self._open:
                raise RuntimeError("Account already open")
            self._open = True
            self._balance = 0

    def close(self):
        with self._lock:
            if not self._open:
                raise RuntimeError("Account already closed")
            if self._balance != 0:
                raise RuntimeError("Cannot close account with non-zero balance")
            self._open = False

    def deposit(self, amount: int) -> int:
        if amount < 0:
            raise ValueError("Negative deposit")
        with self._lock:
            self._ensure_open()
            self._balance += amount
            return self._balance

    def withdraw(self, amount: int) -> int:
        if amount < 0:
            raise ValueError("Negative withdraw")
        with self._lock:
            self._ensure_open()
            if amount > self._balance:
                raise RuntimeError("Insufficient funds")
            self._balance -= amount
            return self._balance

    def get_balance(self) -> int:
        with self._lock:
            self._ensure_open()
            return self._balance

    def _ensure_open(self):
        if not self._open:
            raise RuntimeError("Account is closed")

def _repeat(fn, times):
    for _ in range(times):
        fn()

if __name__ == "__main__":
    # Test 1
    a1 = BankAccount()
    a1.open()
    a1.deposit(200)
    a1.withdraw(50)
    print("Test1 balance (expected 150):", a1.get_balance())

    # Test 2: Concurrent deposits
    a2 = BankAccount()
    a2.open()
    threads2 = 8
    deposits_per_thread2 = 10000
    ts = []
    for _ in range(threads2):
        t = threading.Thread(target=_repeat, args=(lambda: a2.deposit(1), deposits_per_thread2))
        t.start()
        ts.append(t)
    for t in ts:
        t.join()
    print("Test2 balance (expected {}): {}".format(threads2 * deposits_per_thread2, a2.get_balance()))

    # Test 3: Over-withdraw should fail
    a3 = BankAccount()
    a3.open()
    a3.deposit(50)
    try:
        a3.withdraw(100)
        print("Test3 unexpected success")
    except Exception as ex:
        print("Test3 over-withdraw failed as expected:", ex)

    # Test 4: Close then attempt operation should fail
    a4 = BankAccount()
    a4.open()
    a4.deposit(75)
    a4.withdraw(75)
    a4.close()
    try:
        a4.deposit(10)
        print("Test4 unexpected success")
    except Exception as ex:
        print("Test4 operation on closed account failed as expected:", ex)

    # Test 5: Mixed concurrent operations
    a5 = BankAccount()
    a5.open()
    a5.deposit(1000)
    withdraw_threads = 5
    withdraws_per_thread = 100  # total 500
    deposit_threads = 3
    deposits_per_thread = 100   # total 300
    ts5 = []

    for _ in range(withdraw_threads):
        t = threading.Thread(target=_repeat, args=(lambda: (a5.withdraw(1) if True else None), withdraws_per_thread))
        t.start(); ts5.append(t)
    for _ in range(deposit_threads):
        t = threading.Thread(target=_repeat, args=(lambda: a5.deposit(1), deposits_per_thread))
        t.start(); ts5.append(t)
    for t in ts5:
        t.join()
    print("Test5 balance (expected 800):", a5.get_balance())