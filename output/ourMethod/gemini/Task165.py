from collections import Counter
from typing import List

def check_flush(table_cards: List[str], hand_cards: List[str]) -> bool:
    """
    Checks if a flush can be formed from table and hand cards.
    Args:
        table_cards: A list of 5 card strings on the table.
        hand_cards: A list of 2 card strings in hand.
    Returns:
        True if a flush exists, False otherwise.
    """
    if not isinstance(table_cards, list) or len(table_cards) != 5:
        return False
    if not isinstance(hand_cards, list) or len(hand_cards) != 2:
        return False

    all_cards = table_cards + hand_cards
    
    suits = []
    for card in all_cards:
        if not isinstance(card, str) or len(card) < 3 or '_' not in card:
            return False  # Invalid card format
        suit = card[-1]
        if suit not in ('S', 'H', 'D', 'C'):
            return False  # Invalid suit
        suits.append(suit)

    if not suits:
        return False

    suit_counts = Counter(suits)

    return any(count >= 5 for count in suit_counts.values())

if __name__ == '__main__':
    # Test case 1
    table1 = ["A_S", "J_H", "7_D", "8_D", "10_D"]
    hand1 = ["J_D", "3_D"]
    print(f"Test 1: {check_flush(table1, hand1)}")

    # Test case 2
    table2 = ["10_S", "7_S", "9_H", "4_S", "3_S"]
    hand2 = ["K_S", "Q_S"]
    print(f"Test 2: {check_flush(table2, hand2)}")

    # Test case 3
    table3 = ["3_S", "10_H", "10_D", "10_C", "10_S"]
    hand3 = ["3_S", "4_D"]
    print(f"Test 3: {check_flush(table3, hand3)}")

    # Test case 4
    table4 = ["A_C", "K_C", "Q_C", "J_C", "10_C"]
    hand4 = ["2_H", "3_D"]
    print(f"Test 4: {check_flush(table4, hand4)}")

    # Test case 5
    table5 = ["A_H", "A_S", "A_D", "A_C", "K_H"]
    hand5 = ["K_S", "K_D"]
    print(f"Test 5: {check_flush(table5, hand5)}")