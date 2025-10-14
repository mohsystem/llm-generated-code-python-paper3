from typing import List, Dict

def check_flush(table: List[str], hand: List[str]) -> bool:
    if not isinstance(table, list) or not isinstance(hand, list):
        return False
    if len(table) != 5 or len(hand) != 2:
        return False

    def suit_index(card: str) -> int:
        if not isinstance(card, str):
            return -1
        if card.count('_') != 1:
            return -1
        rank, suit = card.split('_', 1)
        if not rank or len(suit) != 1:
            return -1
        s = suit
        mapping = {'S': 0, 'H': 1, 'D': 2, 'C': 3}
        return mapping.get(s, -1)

    table_counts = [0, 0, 0, 0]
    for card in table:
        idx = suit_index(card)
        if idx < 0:
            return False
        table_counts[idx] += 1

    if max(table_counts) < 3:
        return False

    total_counts = table_counts[:]
    for card in hand:
        idx = suit_index(card)
        if idx < 0:
            return False
        total_counts[idx] += 1

    return any(c >= 5 for c in total_counts)


if __name__ == "__main__":
    # Test case 1: diamond flush
    print(check_flush(
        ["A_S", "J_H", "7_D", "8_D", "10_D"],
        ["J_D", "3_D"]
    ))  # True

    # Test case 2: spade flush
    print(check_flush(
        ["10_S", "7_S", "9_H", "4_S", "3_S"],
        ["K_S", "Q_S"]
    ))  # True

    # Test case 3: no flush
    print(check_flush(
        ["3_S", "10_H", "10_D", "10_C", "10_S"],
        ["3_S", "4_D"]
    ))  # False

    # Test case 4: clubs flush using 3 on table + 2 in hand
    print(check_flush(
        ["2_C", "5_C", "9_C", "K_H", "A_D"],
        ["3_C", "7_C"]
    ))  # True

    # Test case 5: four hearts on table, none in hand -> no flush
    print(check_flush(
        ["2_H", "4_H", "6_H", "8_H", "J_D"],
        ["Q_S", "K_C"]
    ))  # False