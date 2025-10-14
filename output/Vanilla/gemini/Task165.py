from collections import Counter

def checkFlush(table_cards, hand_cards):
    """
    Determines if a 5-card flush can be made from 5 table cards and 2 hand cards.

    :param table_cards: A list of 5 strings representing cards on the table.
    :param hand_cards: A list of 2 strings representing cards in hand.
    :return: True if a flush exists, False otherwise.
    """
    all_cards = table_cards + hand_cards
    suits = [card[-1] for card in all_cards]
    suit_counts = Counter(suits)
    
    for count in suit_counts.values():
        if count >= 5:
            return True
            
    return False

if __name__ == '__main__':
    # Test Case 1
    table1 = ["A_S", "J_H", "7_D", "8_D", "10_D"]
    hand1 = ["J_D", "3_D"]
    print(checkFlush(table1, hand1))

    # Test Case 2
    table2 = ["10_S", "7_S", "9_H", "4_S", "3_S"]
    hand2 = ["K_S", "Q_S"]
    print(checkFlush(table2, hand2))

    # Test Case 3
    table3 = ["3_S", "10_H", "10_D", "10_C", "10_S"]
    hand3 = ["3_S", "4_D"]
    print(checkFlush(table3, hand3))

    # Test Case 4
    table4 = ["A_H", "K_H", "Q_H", "J_H", "10_H"]
    hand4 = ["3_S", "4_D"]
    print(checkFlush(table4, hand4))
    
    # Test Case 5
    table5 = ["A_S", "K_S", "Q_S", "J_S", "2_H"]
    hand5 = ["3_D", "4_C"]
    print(checkFlush(table5, hand5))