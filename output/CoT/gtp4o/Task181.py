# Chain-of-Through process in code comments:
# 1) Problem understanding: Thread-safe bank with open/close/deposit/withdraw/get_balance with correctness under concurrency.
# 2) Security requirements: Validate inputs, avoid overflows, handle closed/non-existent accounts gracefully.
# 3) Secure coding generation: Use per-account locks and a dict lock for map safety.
# 4) Code review: Ensure locks released via context managers and no deadlocks (no nested distinct locks).
# 5) Secure code output: Final code with 5 test cases.

import threading
from typing import Optional, Tuple

class Task181:
    class Bank:
        class Account:
            def __init__(self, acc_id: int, initial: int):
                self.id = acc_id
                self.balance = initial  # in cents
                self.open = True
                self.lock = threading.Lock()

        def __init__(self):
            self._accounts = {}
            self._next_id = 1000
            self._accounts_lock = threading.Lock()

        def open_account(self, initial_cents: int) -> int:
            if initial_cents is None or initial_cents < 0:
                return -1
            with self._accounts_lock:
                acc_id = self._next_id
                self._next_id += 1
                self._accounts[acc_id] = Task181.Bank.Account(acc_id, initial_cents)
                return acc_id

        def _get_account(self, acc_id: int) -> Optional['Task181.Bank.Account']:
            with self._accounts_lock:
                return self._accounts.get(acc_id)

        def close_account(self, acc_id: int) -> bool:
            acc = self._get_account(acc_id)
            if acc is None:
                return False
            with acc.lock:
                if not acc.open:
                    return False
                if acc.balance != 0:
                    return False
                acc.open = False
                return True

        def deposit(self, acc_id: int, amount_cents: int) -> bool:
            acc = self._get_account(acc_id)
            if acc is None:
                return False
            if amount_cents is None or amount_cents <= 0:
                return False
            with acc.lock:
                if not acc.open:
                    return False
                # Overflow guard for Python (big ints) not necessary, but we set a logical cap
                max_cents = 9_223_372_036_854_775_807  # mimic Java Long.MAX_VALUE
                if acc.balance > max_cents - amount_cents:
                    return False
                acc.balance += amount_cents
                return True

        def withdraw(self, acc_id: int, amount_cents: int) -> bool:
            acc = self._get_account(acc_id)
            if acc is None:
                return False
            if amount_cents is None or amount_cents <= 0:
                return False
            with acc.lock:
                if not acc.open:
                    return False
                if acc.balance < amount_cents:
                    return False
                acc.balance -= amount_cents
                return True

        def get_balance(self, acc_id: int) -> int:
            acc = self._get_account(acc_id)
            if acc is None:
                return -1
            with acc.lock:
                if not acc.open:
                    return -1
                return acc.balance

    # 5 test cases
    @staticmethod
    def main():
        bank = Task181.Bank()

        # Test 1: Basic operations
        acc1 = bank.open_account(10_000)
        d1 = bank.deposit(acc1, 5_000)
        w1 = bank.withdraw(acc1, 3_000)
        b1 = bank.get_balance(acc1)
        print(f"Test1 balance expected 12000: {b1} ok={d1 and w1 and b1 == 12_000}")

        # Test 2: Concurrent deposits
        acc2 = bank.open_account(0)
        threads = []
        threads_count = 10
        iters = 100
        amount = 1_000
        for _ in range(threads_count):
            t = threading.Thread(target=lambda: [bank.deposit(acc2, amount) for __ in range(iters)])
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        expected2 = threads_count * iters * amount
        b2 = bank.get_balance(acc2)
        print(f"Test2 balance expected {expected2}: {b2} ok={b2 == expected2}")

        # Test 3: Mixed concurrent ops
        acc3 = bank.open_account(500_000)
        dep_threads = []
        wth_threads = []
        dep_count, dep_iters, dep_amt = 4, 100, 1_000
        wth_count, wth_iters, wth_amt = 3, 80, 1_000
        for _ in range(dep_count):
            t = threading.Thread(target=lambda: [bank.deposit(acc3, dep_amt) for __ in range(dep_iters)])
            t.start()
            dep_threads.append(t)
        for _ in range(wth_count):
            t = threading.Thread(target=lambda: [bank.withdraw(acc3, wth_amt) for __ in range(wth_iters)])
            t.start()
            wth_threads.append(t)
        for t in dep_threads + wth_threads:
            t.join()
        expected3 = 500_000 + dep_count*dep_iters*dep_amt - wth_count*wth_iters*wth_amt
        b3 = bank.get_balance(acc3)
        print(f"Test3 balance expected {expected3}: {b3} ok={b3 == expected3}")

        # Test 4: Close account and ensure operations fail
        acc4 = bank.open_account(0)
        close4 = bank.close_account(acc4)
        dep4 = bank.deposit(acc4, 1_000)
        wth4 = bank.withdraw(acc4, 1_000)
        b4 = bank.get_balance(acc4)
        print(f"Test4 close ok={close4} depositFail={not dep4} withdrawFail={not wth4} balanceIsNeg1={b4 == -1}")

        # Test 5: Non-existent account
        fake = 9_999_999
        dep5 = bank.deposit(fake, 100)
        wth5 = bank.withdraw(fake, 100)
        close5 = bank.close_account(fake)
        b5 = bank.get_balance(fake)
        print(f"Test5 all fail: {not dep5 and not wth5 and not close5 and b5 == -1}")

if __name__ == "__main__":
    Task181.main()