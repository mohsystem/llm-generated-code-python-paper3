from typing import List

def checkFlush(table: List[str], hand: List[str]) -> bool:
    def suit_index(card: str) -> int:
        if not isinstance(card, str):
            return -1
        s = card.strip()
        pos = s.rfind('_')
        if pos == -1 or pos + 1 >= len(s):
            return -1
        ch = s[pos + 1].upper()
        mapping = {'S': 0, 'H': 1, 'D': 2, 'C': 3}
        return mapping.get(ch, -1)

    counts = [0, 0, 0, 0]
    table_counts = [0, 0, 0, 0]

    if table is None or hand is None:
        return False

    for card in table:
        idx = suit_index(card)
        if idx >= 0:
            counts[idx] += 1
            table_counts[idx] += 1

    # Optimization: need at least 3 same-suit cards on table
    if max(table_counts) < 3:
        return False

    for card in hand:
        idx = suit_index(card)
        if idx >= 0:
            counts[idx] += 1

    return any(c >= 5 for c in counts)


if __name__ == "__main__":
    tests = [
        (["A_S", "J_H", "7_D", "8_D", "10_D"], ["J_D", "3_D"]),
        (["10_S", "7_S", "9_H", "4_S", "3_S"], ["K_S", "Q_S"]),
        (["3_S", "10_H", "10_D", "10_C", "10_S"], ["3_S", "4_D"]),
        (["2_H", "5_C", "9_D", "K_H", "Q_H"], ["A_H", "3_H"]),
        (["A_C", "2_D", "3_H", "4_S", "5_C"], ["6_D", "7_H"]),
    ]
    for i, (tbl, hnd) in enumerate(tests, 1):
        print(f"Test {i}: {checkFlush(tbl, hnd)}")