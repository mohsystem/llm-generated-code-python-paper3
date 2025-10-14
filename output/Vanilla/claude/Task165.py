
def check_flush(table, hand):
    suit_count = {'S': 0, 'H': 0, 'D': 0, 'C': 0}
    
    # Count suits from table
    for card in table:
        suit = card.split('_')[1]
        suit_count[suit] += 1
    
    # Check each suit
    for suit, count in suit_count.items():
        if count >= 3:
            # Check if hand has cards of this suit
            hand_count = sum(1 for card in hand if card.split('_')[1] == suit)
            # Need at least 5 total cards of same suit
            if count + hand_count >= 5:
                return True
    
    return False

if __name__ == "__main__":
    # Test case 1
    print(check_flush(
        ["A_S", "J_H", "7_D", "8_D", "10_D"], 
        ["J_D", "3_D"]
    ))  # True - diamond flush
    
    # Test case 2
    print(check_flush(
        ["10_S", "7_S", "9_H", "4_S", "3_S"], 
        ["K_S", "Q_S"]
    ))  # True - spade flush
    
    # Test case 3
    print(check_flush(
        ["3_S", "10_H", "10_D", "10_C", "10_S"], 
        ["3_S", "4_D"]
    ))  # False
    
    # Test case 4
    print(check_flush(
        ["2_H", "5_H", "8_H", "K_C", "A_S"], 
        ["9_H", "J_H"]
    ))  # True - heart flush
    
    # Test case 5
    print(check_flush(
        ["2_C", "3_C", "4_C", "5_H", "6_H"], 
        ["7_H", "8_D"]
    ))  # False
