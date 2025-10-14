# Step 1: Problem understanding and function definition
def checkFlush(table, hand):
    counts = {'S': 0, 'H': 0, 'D': 0, 'C': 0}

    # Step 2-4: Secure parsing and counting with input validation
    def add(cards):
        if cards is None:
            return
        for card in cards:
            if not card:
                continue
            try:
                idx = card.index('_')
            except ValueError:
                continue
            if idx + 1 >= len(card):
                continue
            s = card[idx + 1].upper()
            if s in counts:
                counts[s] += 1

    add(table)
    add(hand)
    return any(v >= 5 for v in counts.values())


# Step 5: Main with 5 test cases
if __name__ == "__main__":
    tests = [
        (["A_S", "J_H", "7_D", "8_D", "10_D"], ["J_D", "3_D"]),       # True
        (["10_S", "7_S", "9_H", "4_S", "3_S"], ["K_S", "Q_S"]),       # True
        (["3_S", "10_H", "10_D", "10_C", "10_S"], ["3_S", "4_D"]),    # False
        (["2_H", "5_H", "K_H", "9_C", "J_D"], ["A_H", "3_H"]),        # True
        (["a_s", "j_h", "7_d", "8_d", "10_d"], ["j_d", "3_c"])        # False
    ]
    for i, (table, hand) in enumerate(tests, 1):
        print(f"Test {i}: {checkFlush(table, hand)}")