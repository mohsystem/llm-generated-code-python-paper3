
def check_flush(table: list, hand: list) -> bool:
    # Validate inputs
    if table is None or hand is None:
        return False
    if not isinstance(table, list) or not isinstance(hand, list):
        return False
    if len(table) != 5 or len(hand) != 2:
        return False
    
    # Combine all cards
    all_cards = []
    for card in table:
        if not is_valid_card(card):
            return False
        all_cards.append(card)
    
    for card in hand:
        if not is_valid_card(card):
            return False
        all_cards.append(card)
    
    # Count suits
    suit_count = {}
    for card in all_cards:
        suit = card[-1]
        suit_count[suit] = suit_count.get(suit, 0) + 1
    
    # Check if any suit has 5 or more cards
    for count in suit_count.values():
        if count >= 5:
            return True
    
    return False


def is_valid_card(card) -> bool:
    if not isinstance(card, str):
        return False
    if len(card) < 3:
        return False
    if '_' not in card:
        return False
    
    parts = card.split('_')
    if len(parts) != 2:
        return False
    
    rank, suit = parts
    if len(suit) != 1:
        return False
    if suit not in ['S', 'H', 'D', 'C']:
        return False
    
    return True


if __name__ == "__main__":
    # Test case 1
    print("Test 1:", check_flush(["A_S", "J_H", "7_D", "8_D", "10_D"], ["J_D", "3_D"]))  # True
    
    # Test case 2
    print("Test 2:", check_flush(["10_S", "7_S", "9_H", "4_S", "3_S"], ["K_S", "Q_S"]))  # True
    
    # Test case 3
    print("Test 3:", check_flush(["3_S", "10_H", "10_D", "10_C", "10_S"], ["3_S", "4_D"]))  # False
    
    # Test case 4
    print("Test 4:", check_flush(["2_H", "3_H", "4_H", "5_H", "6_C"], ["7_H", "8_C"]))  # True
    
    # Test case 5
    print("Test 5:", check_flush(["A_C", "K_D", "Q_H", "J_S", "10_C"], ["9_D", "8_H"]))  # False
