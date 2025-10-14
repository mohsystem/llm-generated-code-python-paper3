from collections import deque
from typing import List, Tuple

def reparent(n: int, edges: List[Tuple[int, int]], root: int) -> List[Tuple[int, int]]:
    g = [[] for _ in range(n)]
    for u, v in edges:
        g[u].append(v)
        g[v].append(u)
    vis = [False] * n
    q = deque([root])
    vis[root] = True
    res: List[Tuple[int, int]] = []
    while q:
        u = q.popleft()
        for v in g[u]:
            if not vis[v]:
                vis[v] = True
                res.append((u, v))
                q.append(v)
    return res

def _print_directed_edges(dedges: List[Tuple[int, int]]) -> None:
    s = "[" + ", ".join(f"({u}->{v})" for u, v in dedges) + "]"
    print(s)

def main():
    # Test case 1
    n1 = 10
    edges1 = [(0,1),(0,2),(0,3),(1,4),(1,5),(2,6),(2,7),(3,8),(3,9)]
    print("Test 1: root=6")
    _print_directed_edges(reparent(n1, edges1, 6))

    # Test case 2
    print("Test 2: root=0")
    _print_directed_edges(reparent(n1, edges1, 0))

    # Test case 3
    n3 = 5
    edges3 = [(0,1),(1,2),(2,3),(3,4)]
    print("Test 3: root=3")
    _print_directed_edges(reparent(n3, edges3, 3))

    # Test case 4
    n4 = 6
    edges4 = [(0,1),(0,2),(0,3),(0,4),(0,5)]
    print("Test 4: root=4")
    _print_directed_edges(reparent(n4, edges4, 4))

    # Test case 5
    n5 = 7
    edges5 = [(0,1),(1,2),(1,3),(3,4),(2,5),(5,6)]
    print("Test 5: root=4")
    _print_directed_edges(reparent(n5, edges5, 4))

if __name__ == "__main__":
    main()