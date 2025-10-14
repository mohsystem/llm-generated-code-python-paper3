from __future__ import annotations
import threading
from typing import Dict, Optional

# Error codes
ERR_NO_ACCOUNT_OR_CLOSED = -1
ERR_INSUFFICIENT_FUNDS = -2
ERR_INVALID_INPUT = -3

class Account:
    __slots__ = ("_lock", "balance", "closed")
    def __init__(self, initial: int) -> None:
        self._lock = threading.Lock()
        self.balance: int = initial
        self.closed: bool = False

class Bank:
    def __init__(self) -> None:
        self._accounts: Dict[str, Account] = {}
        self._map_lock = threading.Lock()

    def _valid_id(self, id_: Optional[str]) -> bool:
        if id_ is None:
            return False
        try:
            b = id_.encode("utf-8")
        except Exception:
            return False
        if len(b) == 0 or len(b) > 32:
            return False
        for ch in id_:
            if not (ch.isalnum() or ch in "_-"):
                return False
        return True

    def open_account(self, id_: str, initial_cents: int) -> bool:
        if not self._valid_id(id_) or initial_cents < 0:
            return False
        with self._map_lock:
            if id_ in self._accounts:
                return False
            self._accounts[id_] = Account(initial_cents)
            return True

    def _get_account(self, id_: str) -> Optional[Account]:
        # Return account without holding map lock to reduce contention.
        # Once retrieved, we will lock per-account for safe operations.
        return self._accounts.get(id_)

    def get_balance(self, id_: str) -> int:
        if not self._valid_id(id_):
            return ERR_INVALID_INPUT
        acc = self._get_account(id_)
        if acc is None:
            return ERR_NO_ACCOUNT_OR_CLOSED
        with acc._lock:
            if acc.closed:
                return ERR_NO_ACCOUNT_OR_CLOSED
            return acc.balance

    def deposit(self, id_: str, amount_cents: int) -> int:
        if not self._valid_id(id_) or amount_cents < 0:
            return ERR_INVALID_INPUT
        acc = self._get_account(id_)
        if acc is None:
            return ERR_NO_ACCOUNT_OR_CLOSED
        with acc._lock:
            if acc.closed:
                return ERR_NO_ACCOUNT_OR_CLOSED
            new_bal = acc.balance + amount_cents
            if new_bal < 0:
                return ERR_INVALID_INPUT
            acc.balance = new_bal
            return acc.balance

    def withdraw(self, id_: str, amount_cents: int) -> int:
        if not self._valid_id(id_) or amount_cents < 0:
            return ERR_INVALID_INPUT
        acc = self._get_account(id_)
        if acc is None:
            return ERR_NO_ACCOUNT_OR_CLOSED
        with acc._lock:
            if acc.closed:
                return ERR_NO_ACCOUNT_OR_CLOSED
            if acc.balance < amount_cents:
                return ERR_INSUFFICIENT_FUNDS
            acc.balance -= amount_cents
            return acc.balance

    def close_account(self, id_: str) -> bool:
        if not self._valid_id(id_):
            return False
        acc = self._get_account(id_)
        if acc is None:
            return False
        with acc._lock:
            if acc.closed or acc.balance != 0:
                return False
            acc.closed = True
            return True

def _concurrent_deposit(bank: Bank, acc_id: str, loops: int, amt: int, start_evt: threading.Event) -> None:
    start_evt.wait()
    for _ in range(loops):
        bank.deposit(acc_id, amt)

def _concurrent_withdraw(bank: Bank, acc_id: str, loops: int, amt: int, start_evt: threading.Event) -> None:
    start_evt.wait()
    for _ in range(loops):
        r = bank.withdraw(acc_id, amt)
        if r == ERR_INSUFFICIENT_FUNDS:
            # ignore and continue
            pass

if __name__ == "__main__":
    bank = Bank()

    # Test 1: Open and balance check
    opened1 = bank.open_account("alice", 10_000)
    bal1 = bank.get_balance("alice")
    print(f"Test1: opened={opened1} balance={bal1}")

    # Test 2: Deposit
    bal2 = bank.deposit("alice", 2_500)
    print(f"Test2: deposit newBalance={bal2}")

    # Test 3: Withdraw success
    bal3 = bank.withdraw("alice", 5_000)
    print(f"Test3: withdraw newBalance={bal3}")

    # Test 4: Withdraw insufficient
    w4 = bank.withdraw("alice", 10_000)
    bal4 = bank.get_balance("alice")
    print(f"Test4: withdrawResult={w4} balanceAfter={bal4}")

    # Test 5: Concurrency + close behavior
    acc_id = "bob"
    opened2 = bank.open_account(acc_id, 0)
    deposit_threads = 4
    deposit_iters = 1000
    deposit_amt = 100
    withdraw_threads = 2
    withdraw_iters = 500
    withdraw_amt = 50
    threads = []
    start_evt = threading.Event()
    for _ in range(deposit_threads):
        t = threading.Thread(target=_concurrent_deposit, args=(bank, acc_id, deposit_iters, deposit_amt, start_evt), daemon=True)
        threads.append(t)
        t.start()
    for _ in range(withdraw_threads):
        t = threading.Thread(target=_concurrent_withdraw, args=(bank, acc_id, withdraw_iters, withdraw_amt, start_evt), daemon=True)
        threads.append(t)
        t.start()
    start_evt.set()
    for t in threads:
        t.join()
    final_expected = deposit_threads * deposit_iters * deposit_amt - withdraw_threads * withdraw_iters * withdraw_amt
    bal5 = bank.get_balance(acc_id)
    close_attempt_non_zero = bank.close_account(acc_id)
    withdraw_all = bank.withdraw(acc_id, bal5 if bal5 >= 0 else 0)
    close_attempt_zero = bank.close_account(acc_id)
    post_close_deposit = bank.deposit(acc_id, 100)
    print(f"Test5: opened={opened2} expectedBalance={final_expected} actualBalance={bal5} "
          f"closeNonZero={close_attempt_non_zero} withdrawAllRes={withdraw_all} "
          f"closeZero={close_attempt_zero} depositAfterCloseRes={post_close_deposit}")