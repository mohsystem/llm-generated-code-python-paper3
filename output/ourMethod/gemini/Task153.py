import collections
from typing import List, Set

def bfs(graph: List[List[int]], start_node: int) -> List[int]:
    """
    Performs a Breadth-First Search on a graph.

    Args:
        graph: The graph represented as an adjacency list.
        start_node: The node to start the BFS from.

    Returns:
        A list of nodes in the order they were visited.
    """
    num_vertices = len(graph)
    if not (0 <= start_node < num_vertices):
        print(f"Error: Start node {start_node} is out of bounds.")
        return []

    visited: Set[int] = {start_node}
    queue: collections.deque[int] = collections.deque([start_node])
    result: List[int] = []

    while queue:
        current_node = queue.popleft()
        result.append(current_node)

        for neighbor in graph[current_node]:
            if 0 <= neighbor < num_vertices and neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)

    return result

if __name__ == '__main__':
    # Test Case 1: Simple connected graph
    print("Test Case 1: Simple connected graph")
    g1: List[List[int]] = [[] for _ in range(6)]
    g1[0].extend([1, 2])
    g1[1].append(3)
    g1[2].append(4)
    g1[3].append(5)
    print(f"BFS starting from node 0: {bfs(g1, 0)}")

    # Test Case 2: Start from a different node
    print("\nTest Case 2: Start from a different node")
    g2: List[List[int]] = [[] for _ in range(4)]
    g2[0].extend([1, 2])
    g2[1].append(2)
    g2[2].extend([0, 3])
    g2[3].append(3)
    print(f"BFS starting from node 2: {bfs(g2, 2)}")

    # Test Case 3: Graph with a cycle
    print("\nTest Case 3: Graph with a cycle")
    g3: List[List[int]] = [[] for _ in range(3)]
    g3[0].append(1)
    g3[1].append(2)
    g3[2].append(0)
    print(f"BFS starting from node 0: {bfs(g3, 0)}")

    # Test Case 4: Disconnected graph
    print("\nTest Case 4: Disconnected graph")
    g4: List[List[int]] = [[] for _ in range(5)]
    g4[0].append(1)
    g4[1].append(2)
    g4[3].append(4)
    print(f"BFS starting from node 0: {bfs(g4, 0)}")
    print(f"BFS starting from node 3: {bfs(g4, 3)}")

    # Test Case 5: Invalid start node
    print("\nTest Case 5: Invalid start node")
    g5: List[List[int]] = [[] for _ in range(3)]
    g5[0].append(1)
    print(f"BFS starting from node 5: {bfs(g5, 5)}")