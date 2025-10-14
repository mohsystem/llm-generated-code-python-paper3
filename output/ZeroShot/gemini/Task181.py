import threading
import time
from itertools import count

class BankAccount:
    def __init__(self, initial_balance=0):
        if initial_balance < 0:
            raise ValueError("Initial balance cannot be negative")
        self._balance = initial_balance
        self._is_open = True
        self._lock = threading.Lock()

    def get_balance(self):
        with self._lock:
            if not self._is_open:
                return None
            return self._balance

    def deposit(self, amount):
        if amount <= 0:
            return False
        with self._lock:
            if not self._is_open:
                return False
            self._balance += amount
            return True

    def withdraw(self, amount):
        if amount <= 0:
            return False
        with self._lock:
            if not self._is_open:
                return False
            if self._balance < amount:
                return False
            self._balance -= amount
            return True

    def close(self):
        with self._lock:
            self._is_open = False
            # We can optionally set balance to 0, but just marking it closed is enough.
            return True

# --- Global Bank Management ---
_accounts = {}
_next_account_id = count(1)
_bank_lock = threading.Lock() # Lock to protect the global _accounts dictionary

def open_account(initial_balance=0):
    if initial_balance < 0:
        return None
    account_id = next(_next_account_id)
    with _bank_lock:
        _accounts[account_id] = BankAccount(initial_balance)
    return account_id

def get_account(account_id):
    with _bank_lock:
        return _accounts.get(account_id)

def close_account(account_id):
    account = get_account(account_id)
    if account:
        account.close()
        # With _bank_lock:
        #     del _accounts[account_id]  # Optionally remove from dict
        return True
    return False

def deposit(account_id, amount):
    account = get_account(account_id)
    if account:
        return account.deposit(amount)
    return False

def withdraw(account_id, amount):
    account = get_account(account_id)
    if account:
        return account.withdraw(amount)
    return False

def get_balance(account_id):
    account = get_account(account_id)
    if account:
        return account.get_balance()
    return None

# --- Main function with test cases ---
def main():
    print("--- Python Bank Test Cases ---")

    # Test Case 1: Simple deposit and withdrawal
    print("\n--- Test Case 1: Simple Operations ---")
    acc1 = open_account(100)
    print(f"Opened account {acc1} with balance: {get_balance(acc1)}")
    deposit(acc1, 50)
    print(f"Deposited 50. New balance: {get_balance(acc1)}")
    withdraw(acc1, 30)
    print(f"Withdrew 30. Final balance: {get_balance(acc1)}")

    # Test Case 2: Insufficient funds
    print("\n--- Test Case 2: Insufficient Funds ---")
    acc2 = open_account(50)
    print(f"Opened account {acc2} with balance: {get_balance(acc2)}")
    success = withdraw(acc2, 100)
    print(f"Attempted to withdraw 100. Success: {success}")
    print(f"Final balance: {get_balance(acc2)}")

    # Test Case 3: Operations on a closed account
    print("\n--- Test Case 3: Closed Account Operations ---")
    acc3 = open_account(200)
    print(f"Opened account {acc3} with balance: {get_balance(acc3)}")
    close_account(acc3)
    print(f"Account {acc3} closed.")
    print(f"Attempting deposit of 50. Success: {deposit(acc3, 50)}")
    print(f"Attempting withdrawal of 20. Success: {withdraw(acc3, 20)}")
    print(f"Final balance: {get_balance(acc3)}")

    # Test Case 4: Concurrent deposits
    print("\n--- Test Case 4: Concurrent Deposits ---")
    acc4 = open_account(0)
    print(f"Opened account {acc4} with balance: {get_balance(acc4)}")
    threads = []
    for _ in range(10):
        thread = threading.Thread(target=deposit, args=(acc4, 10))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    print(f"After 10 threads each deposited 10, final balance: {get_balance(acc4)}")

    # Test Case 5: Concurrent deposits and withdrawals
    print("\n--- Test Case 5: Concurrent Mix ---")
    acc5 = open_account(1000)
    print(f"Opened account {acc5} with balance: {get_balance(acc5)}")
    threads = []
    for i in range(10):
        if i % 2 == 0:
             # 5 threads depositing 20 each
            thread = threading.Thread(target=deposit, args=(acc5, 20))
        else:
            # 5 threads withdrawing 30 each
            thread = threading.Thread(target=withdraw, args=(acc5, 30))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    # Expected: 1000 + (5*20) - (5*30) = 950
    print(f"After 5 deposits of 20 and 5 withdrawals of 30, final balance: {get_balance(acc5)}")

if __name__ == "__main__":
    main()