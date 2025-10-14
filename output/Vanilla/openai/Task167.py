def cubeDiagonal(volume):
    return round((volume ** (1/3)) * (3 ** 0.5), 2)

if __name__ == "__main__":
    tests = [8, 343, 1157.625, 1, 0.125]
    for v in tests:
        res = cubeDiagonal(v)
        print(f"{res:.2f}")