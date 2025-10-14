import collections

def check_flush(table, hand):
    """
    Determines if a flush exists given 5 table cards and 2 hand cards.
    A flush is 5 or more cards of the same suit.

    Args:
        table (list): A list of 5 strings representing the cards on the table.
        hand (list): A list of 2 strings representing the cards in hand.

    Returns:
        bool: True if a flush exists, False otherwise.
    """
    # Securely validate input to prevent TypeErrors or IndexErrors
    if not isinstance(table, list) or not isinstance(hand, list) or len(table) != 5 or len(hand) != 2:
        return False

    all_cards = table + hand
    
    suits = []
    for card in all_cards:
        # Check for valid card string format
        if isinstance(card, str) and len(card) >= 2 and '_' in card:
            suits.append(card[-1])

    if not suits:
        return False
        
    suit_counts = collections.Counter(suits)
    
    # Check if any suit count is 5 or more
    for count in suit_counts.values():
        if count >= 5:
            return True
            
    return False

if __name__ == "__main__":
    # Test Case 1: Diamond flush
    table1 = ["A_S", "J_H", "7_D", "8_D", "10_D"]
    hand1 = ["J_D", "3_D"]
    print(f"Test Case 1: {check_flush(table1, hand1)}")

    # Test Case 2: Spade flush (6 spades)
    table2 = ["10_S", "7_S", "9_H", "4_S", "3_S"]
    hand2 = ["K_S", "Q_S"]
    print(f"Test Case 2: {check_flush(table2, hand2)}")

    # Test Case 3: No flush
    table3 = ["3_S", "10_H", "10_D", "10_C", "10_S"]
    hand3 = ["3_S", "4_D"]
    print(f"Test Case 3: {check_flush(table3, hand3)}")

    # Test Case 4: No flush (4 Hearts, 3 Diamonds)
    table4 = ["A_H", "2_H", "3_H", "4_H", "5_D"]
    hand4 = ["6_D", "7_D"]
    print(f"Test Case 4: {check_flush(table4, hand4)}")

    # Test Case 5: No flush (3 Clubs, 4 Spades)
    table5 = ["A_C", "2_C", "3_C", "4_S", "5_S"]
    hand5 = ["6_S", "7_S"]
    print(f"Test Case 5: {check_flush(table5, hand5)}")