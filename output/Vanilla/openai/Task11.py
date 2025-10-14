def nb_year(p0, percent, aug, p):
    years = 0
    while p0 < p:
        p0 += int(p0 * percent / 100.0) + aug
        years += 1
    return years

if __name__ == "__main__":
    print(nb_year(1000, 2, 50, 1200))          # Expected: 3
    print(nb_year(1500, 5, 100, 5000))         # Expected: 15
    print(nb_year(1500000, 2.5, 10000, 2000000)) # Expected: 10
    print(nb_year(1500, 0, 100, 2000))         # Expected: 5
    print(nb_year(100, 5, 0, 101))             # Expected: 1