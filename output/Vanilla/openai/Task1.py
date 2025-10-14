def number(stops):
    return sum(on - off for on, off in stops)

if __name__ == "__main__":
    t1 = [(10, 0), (3, 5), (5, 8)]
    t2 = [(3, 0), (9, 1), (4, 10), (12, 2), (6, 1), (7, 10)]
    t3 = [(0, 0)]
    t4 = [(5, 0), (0, 0), (0, 0)]
    t5 = [(21, 0), (0, 20), (1, 0)]
    print(number(t1))
    print(number(t2))
    print(number(t3))
    print(number(t4))
    print(number(t5))