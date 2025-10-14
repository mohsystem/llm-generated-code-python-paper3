import threading
from typing import Optional

class Bank:
    class Account:
        __slots__ = ("lock", "balance", "closed")
        def __init__(self, initial: int):
            self.lock = threading.Lock()
            self.balance = initial
            self.closed = False

    def __init__(self):
        self._accounts = {}
        self._accounts_lock = threading.Lock()
        self._next_id = 1

    def open_account(self, initial_cents: int) -> int:
        if initial_cents < 0:
            return -1
        with self._accounts_lock:
            acc_id = self._next_id
            self._next_id += 1
            self._accounts[acc_id] = Bank.Account(initial_cents)
            return acc_id

    def close_account(self, account_id: int) -> bool:
        with self._accounts_lock:
            acc = self._accounts.get(account_id)
        if acc is None:
            return False
        with acc.lock:
            if acc.closed:
                return False
            acc.closed = True
            return True

    def deposit(self, account_id: int, cents: int) -> bool:
        if cents <= 0:
            return False
        with self._accounts_lock:
            acc = self._accounts.get(account_id)
        if acc is None:
            return False
        with acc.lock:
            if acc.closed:
                return False
            # Python ints are unbounded, but we still validate sign
            acc.balance += cents
            return True

    def withdraw(self, account_id: int, cents: int) -> bool:
        if cents <= 0:
            return False
        with self._accounts_lock:
            acc = self._accounts.get(account_id)
        if acc is None:
            return False
        with acc.lock:
            if acc.closed:
                return False
            if cents > acc.balance:
                return False
            acc.balance -= cents
            return True

    def get_balance(self, account_id: int) -> Optional[int]:
        with self._accounts_lock:
            acc = self._accounts.get(account_id)
        if acc is None:
            return None
        with acc.lock:
            if acc.closed:
                return None
            return acc.balance

def _run_concurrent(func, threads: int):
    start = threading.Event()
    done = []
    lock = threading.Lock()
    def wrapper():
        start.wait()
        func()
        with lock:
            done.append(1)
    ts = [threading.Thread(target=wrapper) for _ in range(threads)]
    for t in ts:
        t.start()
    start.set()
    for t in ts:
        t.join()

if __name__ == "__main__":
    bank = Bank()

    # Test 1
    a1 = bank.open_account(10_000)
    d1 = bank.deposit(a1, 5_000)
    w1 = bank.withdraw(a1, 2_000)
    b1 = bank.get_balance(a1)
    print("Test1:", d1 and w1 and b1 == 13_000)

    # Test 2: Concurrent deposits
    a2 = bank.open_account(0)
    threads2 = 10
    per_thread_ops2 = 1000
    per_op2 = 1_000
    def work2():
        for _ in range(per_thread_ops2):
            bank.deposit(a2, per_op2)
    _run_concurrent(work2, threads2)
    b2 = bank.get_balance(a2)
    expected2 = threads2 * per_thread_ops2 * per_op2
    print("Test2:", b2 == expected2)

    # Test 3: Mixed operations
    a3 = bank.open_account(1_000_000)
    threads3 = 8
    per_thread_ops3 = 5000
    def work3():
        for _ in range(per_thread_ops3):
            bank.deposit(a3, 100)
            bank.withdraw(a3, 100)
    _run_concurrent(work3, threads3)
    b3 = bank.get_balance(a3)
    print("Test3:", b3 == 1_000_000)

    # Test 4: Close then fail ops
    a4 = bank.open_account(50_000)
    c4 = bank.close_account(a4)
    d4 = bank.deposit(a4, 1_000)
    w4 = bank.withdraw(a4, 1_000)
    b4 = bank.get_balance(a4)
    print("Test4:", c4 and (d4 is False) and (w4 is False) and (b4 is None))

    # Test 5: Insufficient and invalid
    a5 = bank.open_account(5_000)
    w5a = bank.withdraw(a5, 10_000)
    d5a = bank.deposit(a5, -100)
    w5b = bank.withdraw(a5, 0)
    b5 = bank.get_balance(a5)
    print("Test5:", (w5a is False) and (d5a is False) and (w5b is False) and b5 == 5_000)