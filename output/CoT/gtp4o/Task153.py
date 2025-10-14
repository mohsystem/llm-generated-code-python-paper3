# Secure BFS implementation in Python with test cases.
from collections import deque

def bfs(graph, start):
    """
    Performs a BFS on a graph represented as a dict: node -> list of neighbors.
    Returns the visitation order as a list. If graph is None, treats as empty.
    """
    # Security and robustness:
    # - Treat None graph as empty
    # - Ignore None neighbors
    # - No mutation of input graph
    order = []
    visited = set()
    q = deque()

    visited.add(start)
    q.append(start)

    while q:
        cur = q.popleft()
        order.append(cur)
        neighbors = []
        if graph is not None:
            neighbors = graph.get(cur, [])
        for nb in neighbors:
            if nb is None:
                continue
            if nb not in visited:
                visited.add(nb)
                q.append(nb)
    return order

def _print_result(label, result):
    print(f"{label}: {result}")

if __name__ == "__main__":
    # Test 1: Simple chain 0-1-2-3 (undirected)
    g1 = {
        0: [1],
        1: [0, 2],
        2: [1, 3],
        3: [2]
    }
    _print_result("Test1", bfs(g1, 0))  # expected [0,1,2,3]

    # Test 2: Cycle 1-2-3-1 with branch 2-4 (undirected)
    g2 = {
        1: [2, 3],
        2: [1, 3, 4],
        3: [2, 1],
        4: [2]
    }
    _print_result("Test2", bfs(g2, 1))  # expected [1,2,3,4]

    # Test 3: Disconnected with isolated node 5
    g3 = {5: []}
    _print_result("Test3", bfs(g3, 5))  # expected [5]

    # Test 4: Ordered neighbors for 0: [3, 1, 2]
    g4 = {
        0: [3, 1, 2],
        1: [4],
        2: [],
        3: [5],
        4: [],
        5: []
    }
    _print_result("Test4", bfs(g4, 0))  # expected [0,3,1,2,5,4]

    # Test 5: Start not present in graph
    g5 = {10: [11], 11: [10]}
    _print_result("Test5", bfs(g5, 99))  # expected [99]