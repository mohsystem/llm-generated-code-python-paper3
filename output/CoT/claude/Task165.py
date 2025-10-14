
def check_flush(table, hand):
    # Input validation
    if not table or not hand or len(table) != 5 or len(hand) != 2:
        return False
    
    # Count suits from all cards
    suit_count = {'S': 0, 'H': 0, 'D': 0, 'C': 0}
    
    # Process all cards
    all_cards = table + hand
    
    for card in all_cards:
        if not card or '_' not in card:
            continue
        
        # Safe extraction of suit
        parts = card.split('_')
        if len(parts) >= 2:
            suit = parts[-1]
            if suit in suit_count:
                suit_count[suit] += 1
    
    # Check if any suit has at least 5 cards (flush)
    return any(count >= 5 for count in suit_count.values())


if __name__ == "__main__":
    # Test case 1: Diamond flush
    print(check_flush(["A_S", "J_H", "7_D", "8_D", "10_D"], ["J_D", "3_D"]))  # True
    
    # Test case 2: Spade flush
    print(check_flush(["10_S", "7_S", "9_H", "4_S", "3_S"], ["K_S", "Q_S"]))  # True
    
    # Test case 3: No flush
    print(check_flush(["3_S", "10_H", "10_D", "10_C", "10_S"], ["3_S", "4_D"]))  # False
    
    # Test case 4: Heart flush
    print(check_flush(["2_H", "5_H", "8_H", "K_H", "A_S"], ["Q_H", "J_H"]))  # True
    
    # Test case 5: Club flush
    print(check_flush(["9_C", "7_C", "4_C", "2_C", "K_H"], ["6_C", "3_D"]))  # True
