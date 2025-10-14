def checkFlush(table, hand):
    counts = {'S': 0, 'H': 0, 'D': 0, 'C': 0}
    def suit(card):
        return card.split('_')[-1][0] if '_' in card else '?'
    for c in table + hand:
        s = suit(c)
        if s in counts:
            counts[s] += 1
    return any(v >= 5 for v in counts.values())


if __name__ == "__main__":
    print(checkFlush(["A_S", "J_H", "7_D", "8_D", "10_D"], ["J_D", "3_D"]))  # True
    print(checkFlush(["10_S", "7_S", "9_H", "4_S", "3_S"], ["K_S", "Q_S"]))  # True
    print(checkFlush(["3_S", "10_H", "10_D", "10_C", "10_S"], ["3_S", "4_D"]))  # False
    print(checkFlush(["2_H", "5_H", "7_H", "9_H", "K_H"], ["A_S", "3_D"]))  # True
    print(checkFlush(["2_C", "5_C", "7_C", "9_H", "K_D"], ["A_C", "3_D"]))  # False