# Chain-of-Through steps applied: understanding, secure design, implementation, review, and safe output.
# Python implementation with function and 5 test cases.

def nb_year(p0: int, percent: float, aug: int, p: int) -> int:
    if p0 >= p:
        return 0
    pop = p0
    years = 0
    rate = percent / 100.0
    # Prevent infinite loop by checking progress
    while pop < p:
        prev = pop
        pop += int(pop * rate) + aug  # floor via int()
        years += 1
        if pop <= prev or years > 10_000_000:
            return -1
    return years

if __name__ == "__main__":
    # 5 test cases
    print(nb_year(1000, 2, 50, 1200))              # 3
    print(nb_year(1500, 5, 100, 5000))             # 15
    print(nb_year(1500000, 2.5, 10000, 2000000))   # 10
    print(nb_year(1500000, 0, 10000, 2000000))     # 50
    print(nb_year(1000, 0, -1, 1200))              # -1