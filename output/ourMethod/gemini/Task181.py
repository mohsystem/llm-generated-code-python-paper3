import threading

class Bank:
    def __init__(self):
        self._accounts = {}
        self._next_account_id = 1
        # Lock for operations on the _accounts dictionary itself (add/remove)
        self._lock = threading.Lock()

    def _get_account(self, account_id):
        # We don't need to lock the dictionary for read access here because
        # we don't remove accounts, we just mark them as closed.
        # If we were removing accounts, a lock would be needed.
        return self._accounts.get(account_id)

    def open_account(self, initial_balance: float) -> int:
        if initial_balance < 0:
            raise ValueError("Initial balance cannot be negative.")
        
        with self._lock:
            account_id = self._next_account_id
            self._accounts[account_id] = self._Account(initial_balance)
            self._next_account_id += 1
            return account_id

    def close_account(self, account_id: int):
        account = self._get_account(account_id)
        if not account:
            raise ValueError("Account not found")
        account.close()

    def deposit(self, account_id: int, amount: float):
        if amount <= 0:
            raise ValueError("Deposit amount must be positive.")
        account = self._get_account(account_id)
        if not account:
            raise ValueError("Account not found")
        account.deposit(amount)

    def withdraw(self, account_id: int, amount: float):
        if amount <= 0:
            raise ValueError("Withdrawal amount must be positive.")
        account = self._get_account(account_id)
        if not account:
            raise ValueError("Account not found")
        account.withdraw(amount)

    def get_balance(self, account_id: int) -> float:
        account = self._get_account(account_id)
        if not account:
            raise ValueError("Account not found")
        return account.get_balance()

    class _Account:
        def __init__(self, initial_balance: float):
            self._balance = initial_balance
            self._is_open = True
            self._lock = threading.Lock()

        def deposit(self, amount: float):
            with self._lock:
                if not self._is_open:
                    raise ValueError("Account is closed.")
                self._balance += amount

        def withdraw(self, amount: float):
            with self._lock:
                if not self._is_open:
                    raise ValueError("Account is closed.")
                if self._balance < amount:
                    raise ValueError("Insufficient funds.")
                self._balance -= amount

        def get_balance(self) -> float:
            with self._lock:
                if not self._is_open:
                    raise ValueError("Account is closed.")
                return self._balance

        def close(self):
            with self._lock:
                self._is_open = False


def main():
    bank = Bank()
    print("--- Bank System Test ---")

    # Test Case 1: Open an account and check initial balance
    print("\n--- Test Case 1: Open Account ---")
    acc1 = bank.open_account(100.0)
    print(f"Opened account {acc1} with balance: {bank.get_balance(acc1)}")

    # Test Case 2: Deposit money
    print("\n--- Test Case 2: Deposit ---")
    print(f"Depositing 50.0 into account {acc1}")
    bank.deposit(acc1, 50.0)
    print(f"New balance for account {acc1}: {bank.get_balance(acc1)}")

    # Test Case 3: Withdraw money
    print("\n--- Test Case 3: Withdraw ---")
    print(f"Withdrawing 30.0 from account {acc1}")
    bank.withdraw(acc1, 30.0)
    print(f"New balance for account {acc1}: {bank.get_balance(acc1)}")

    # Test Case 4: Attempt to withdraw more than available funds
    print("\n--- Test Case 4: Insufficient Funds ---")
    try:
        print(f"Attempting to withdraw 200.0 from account {acc1}")
        bank.withdraw(acc1, 200.0)
    except ValueError as e:
        print(f"Caught expected exception: {e}")
        print(f"Balance remains: {bank.get_balance(acc1)}")

    # Test Case 5: Close account and attempt a transaction
    print("\n--- Test Case 5: Closed Account ---")
    print(f"Closing account {acc1}")
    bank.close_account(acc1)
    try:
        print(f"Attempting to deposit 10.0 into closed account {acc1}")
        bank.deposit(acc1, 10.0)
    except ValueError as e:
        print(f"Caught expected exception: {e}")
    try:
        print(f"Attempting to get balance of closed account {acc1}")
        bank.get_balance(acc1)
    except ValueError as e:
        print(f"Caught expected exception: {e}")

if __name__ == "__main__":
    main()