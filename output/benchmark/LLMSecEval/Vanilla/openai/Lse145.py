class Lse145:
    _db = []
    _next_id = 1

    @staticmethod
    def buy_function(stock_name: str):
        if stock_name is None:
            return None
        s = stock_name.strip()
        if not s:
            return None
        return s.upper()

    @staticmethod
    def buy_stock(stock_name: str, quantity: int) -> int:
        normalized = Lse145.buy_function(stock_name)
        if normalized is None or quantity <= 0:
            return -1
        rec = {
            "id": Lse145._next_id,
            "stock": normalized,
            "qty": quantity,
            "ts": __import__("time").time(),
        }
        Lse145._db.append(rec)
        Lse145._next_id += 1
        return rec["id"]

    @staticmethod
    def get_all_records():
        return list(Lse145._db)


if __name__ == "__main__":
    id1 = Lse145.buy_stock("AAPL", 10)
    id2 = Lse145.buy_stock("goog", 5)
    id3 = Lse145.buy_stock("  msft  ", 20)
    id4 = Lse145.buy_stock("", 7)       # invalid
    id5 = Lse145.buy_stock("TSLA", -3)  # invalid

    print("Inserted IDs:", [id1, id2, id3, id4, id5])
    print("Database contents:")
    for r in Lse145.get_all_records():
        print(f"ID={r['id']} Stock={r['stock']} Qty={r['qty']} Ts={r['ts']}")