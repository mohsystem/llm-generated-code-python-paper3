from collections import deque
from typing import List


def bfs(n: int, adjacency: List[List[int]], start: int) -> List[int]:
    _validate_graph(n, adjacency, start)

    visited = [False] * n
    order: List[int] = []
    q: deque[int] = deque()

    visited[start] = True
    q.append(start)

    while q:
        u = q.popleft()
        order.append(u)
        for v in adjacency[u]:
            # neighbors already validated
            if not visited[v]:
                visited[v] = True
                q.append(v)
    return order


def _validate_graph(n: int, adjacency: List[List[int]], start: int) -> None:
    if not isinstance(n, int) or n < 0:
        raise ValueError("n must be an integer >= 0")
    if adjacency is None or not isinstance(adjacency, list):
        raise ValueError("adjacency must be a list")
    if len(adjacency) != n:
        raise ValueError("adjacency size must equal n")
    if n == 0:
        raise ValueError("graph has no nodes")
    if not isinstance(start, int) or start < 0 or start >= n:
        raise ValueError("start node out of range")
    for i, neighbors in enumerate(adjacency):
        if neighbors is None or not isinstance(neighbors, list):
            raise ValueError(f"adjacency list at index {i} is invalid")
        for v in neighbors:
            if not isinstance(v, int) or v < 0 or v >= n:
                raise ValueError(f"edge from {i} to invalid node {v}")


def _print_order(order: List[int]) -> None:
    print("[" + " ".join(str(x) for x in order) + "]")


def main() -> None:
    # Test case 1: Simple line graph 0-1-2-3 from 0
    try:
        n1 = 4
        adj1 = [
            [1],
            [2],
            [3],
            []
        ]
        res1 = bfs(n1, adj1, 0)
        print("Test 1:", end=" ")
        _print_order(res1)
    except ValueError as e:
        print("Test 1 Error:", str(e))

    # Test case 2: Graph with cycles
    try:
        n2 = 4
        adj2 = [
            [1, 2],  # 0
            [2],     # 1
            [0, 3],  # 2
            []       # 3
        ]
        res2 = bfs(n2, adj2, 1)
        print("Test 2:", end=" ")
        _print_order(res2)
    except ValueError as e:
        print("Test 2 Error:", str(e))

    # Test case 3: Disconnected graph start at 3
    try:
        n3 = 5
        adj3 = [
            [1],  # 0
            [2],  # 1
            [],   # 2
            [4],  # 3
            []    # 4
        ]
        res3 = bfs(n3, adj3, 3)
        print("Test 3:", end=" ")
        _print_order(res3)
    except ValueError as e:
        print("Test 3 Error:", str(e))

    # Test case 4: Invalid start node
    try:
        n4 = 3
        adj4 = [
            [1],
            [2],
            []
        ]
        res4 = bfs(n4, adj4, 5)
        print("Test 4:", end=" ")
        _print_order(res4)
    except ValueError as e:
        print("Test 4 Error:", str(e))

    # Test case 5: Invalid edge reference
    try:
        n5 = 3
        adj5 = [
            [1, 99],  # invalid neighbor
            [2],
            []
        ]
        res5 = bfs(n5, adj5, 0)
        print("Test 5:", end=" ")
        _print_order(res5)
    except ValueError as e:
        print("Test 5 Error:", str(e))


if __name__ == "__main__":
    main()