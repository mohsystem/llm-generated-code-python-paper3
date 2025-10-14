def find_nb(m):
    total_volume = 0
    n = 0
    while total_volume < m:
        n += 1
        total_volume += n**3
    
    if total_volume == m:
        return n
    else:
        return -1

if __name__ == '__main__':
    print(f"find_nb(1071225) -> {find_nb(1071225)}")
    print(f"find_nb(91716553919377) -> {find_nb(91716553919377)}")
    print(f"find_nb(4183059834009) -> {find_nb(4183059834009)}")
    print(f"find_nb(1) -> {find_nb(1)}")
    print(f"find_nb(135440716410000) -> {find_nb(135440716410000)}")