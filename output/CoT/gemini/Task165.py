def checkFlush(table, hand):
    """
    Determines if a flush is possible given 5 table cards and 2 hand cards.
    A flush is 5 or more cards of the same suit.

    Args:
        table: A list of 5 strings representing cards on the table.
        hand: A list of 2 strings representing cards in hand.
    
    Returns:
        True if a flush exists, False otherwise.
    """
    all_cards = table + hand
    suit_counts = {'S': 0, 'H': 0, 'D': 0, 'C': 0}

    for card in all_cards:
        if card:  # Check for non-empty string
            suit = card[-1]
            if suit in suit_counts:
                suit_counts[suit] += 1
            
    for count in suit_counts.values():
        if count >= 5:
            return True
            
    return False

if __name__ == '__main__':
    # Test Case 1
    table1 = ["A_S", "J_H", "7_D", "8_D", "10_D"]
    hand1 = ["J_D", "3_D"]
    print(f"Test Case 1: {checkFlush(table1, hand1)}")

    # Test Case 2
    table2 = ["10_S", "7_S", "9_H", "4_S", "3_S"]
    hand2 = ["K_S", "Q_S"]
    print(f"Test Case 2: {checkFlush(table2, hand2)}")

    # Test Case 3
    table3 = ["3_S", "10_H", "10_D", "10_C", "10_S"]
    hand3 = ["3_S", "4_D"]
    print(f"Test Case 3: {checkFlush(table3, hand3)}")

    # Test Case 4
    table4 = ["A_H", "A_S", "A_D", "A_C", "2_H"]
    hand4 = ["3_H", "4_H"]
    print(f"Test Case 4: {checkFlush(table4, hand4)}")

    # Test Case 5
    table5 = ["K_C", "Q_C", "J_C", "3_S", "4_H"]
    hand5 = ["10_C", "9_C"]
    print(f"Test Case 5: {checkFlush(table5, hand5)}")