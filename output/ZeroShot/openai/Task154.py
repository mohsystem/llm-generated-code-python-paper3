from typing import List

def dfs(n: int, graph: List[List[int]], start: int) -> List[int]:
    result: List[int] = []
    if n <= 0 or graph is None or len(graph) != n or start < 0 or start >= n:
        return result

    # Sanitize adjacency: bounds-check, deduplicate, sort ascending
    adj: List[List[int]] = []
    for i in range(n):
        seen = set()
        cleaned = []
        neighbors = graph[i] if graph[i] is not None else []
        for v in neighbors:
            if isinstance(v, int) and 0 <= v < n and v not in seen:
                seen.add(v)
                cleaned.append(v)
        cleaned.sort()
        adj.append(cleaned)

    visited = [False] * n
    stack: List[int] = [start]

    while stack:
        v = stack.pop()
        if v < 0 or v >= n:
            continue
        if not visited[v]:
            visited[v] = True
            result.append(v)
            # Push in reverse sorted order so pop yields ascending visitation
            for nb in reversed(adj[v]):
                if not visited[nb]:
                    stack.append(nb)
    return result

def _print(lst: List[int]) -> None:
    print(lst)

if __name__ == "__main__":
    # Test 1: Simple chain 0-1-2
    n1 = 3
    g1 = [
        [1],
        [0, 2],
        [1]
    ]
    _print(dfs(n1, g1, 0))  # Expected: [0, 1, 2]

    # Test 2: Cycle 0-1-2-3-0
    n2 = 4
    g2 = [
        [1, 3],
        [0, 2],
        [1, 3],
        [2, 0]
    ]
    _print(dfs(n2, g2, 1))

    # Test 3: Disconnected graph
    n3 = 5
    g3 = [
        [],
        [2],
        [1],
        [4],
        [3]
    ]
    _print(dfs(n3, g3, 3))  # Expected: [3, 4]

    # Test 4: Self-loop and out-of-range neighbor
    n4 = 4
    g4 = [
        [0, 1],
        [0, 2, 4],  # 4 ignored
        [1, 3],
        [2]
    ]
    _print(dfs(n4, g4, 0))  # Expected: [0, 1, 2, 3]

    # Test 5: Star graph centered at 0
    n5 = 6
    g5 = [
        [1, 2, 3, 4, 5],
        [0],
        [0],
        [0],
        [0],
        [0]
    ]
    _print(dfs(n5, g5, 2))