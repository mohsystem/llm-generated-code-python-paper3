def nb_year(p0: int, percent: float, aug: int, p: int) -> int:
    if p0 <= 0 or p <= 0 or percent < 0.0:
        return -1
    if p0 >= p:
        return 0
    if percent <= 0.0 and aug <= 0:
        return -1
    pop = int(p0)
    years = 0
    MAX_YEARS = 10_000_000
    while pop < p and years < MAX_YEARS:
        growth = int((pop * (percent / 100.0)) // 1)
        next_pop = pop + growth + aug
        if next_pop == pop:
            return -1
        pop = next_pop
        years += 1
    return years if pop >= p else -1


if __name__ == "__main__":
    # 5 test cases
    print(nb_year(1000, 2, 50, 1200))            # expected 3
    print(nb_year(1500, 5, 100, 5000))           # expected 15
    print(nb_year(1500000, 2.5, 10000, 2000000)) # expected 10
    print(nb_year(1000, 0, -1, 1200))            # expected -1
    print(nb_year(5000, 2, 100, 3000))           # expected 0