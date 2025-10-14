def dfs(v_count, adj, start_node):
    """
    Performs an iterative Depth-First Search (DFS) on a graph.
    
    :param v_count: The number of vertices in the graph.
    :param adj: The adjacency list representation of the graph.
    :param start_node: The node to start the search from.
    :return: A list of integers representing the DFS traversal order.
    """
    # --- Security: Input Validation ---
    if not isinstance(v_count, int) or v_count <= 0 or \
       not isinstance(adj, list) or len(adj) != v_count or \
       not isinstance(start_node, int) or not (0 <= start_node < v_count):
        # Return an empty list for invalid input to prevent errors.
        return []

    visited = [False] * v_count
    # Using a list as a stack is a common and safe practice in Python.
    stack = [start_node]
    result = []

    while stack:
        u = stack.pop()

        if not visited[u]:
            visited[u] = True
            result.append(u)

            # Get all adjacent vertices of the popped vertex u.
            # We iterate in reverse to approximate the order of a recursive DFS.
            for v in reversed(adj[u]):
                # --- Security: Check neighbor validity ---
                if 0 <= v < v_count and not visited[v]:
                    stack.append(v)
    
    return result

def main():
    """Main function with test cases."""
    
    print("--- 5 Test Cases for DFS ---")

    # Test Case 1: Connected Graph, Start 0
    v1 = 7
    adj1 = [[] for _ in range(v1)]
    edges1 = [(0, 1), (0, 3), (1, 2), (1, 4), (2, 1), (3, 0), (3, 4), (3, 5),
              (4, 1), (4, 3), (5, 3), (5, 6), (6, 5)]
    for u, v in edges1:
        adj1[u].append(v)
    print(f"Test Case 1 (Connected Graph, Start 0): {dfs(v1, adj1, 0)}")

    # Test Case 2: Connected Graph, Start 4
    print(f"Test Case 2 (Connected Graph, Start 4): {dfs(v1, adj1, 4)}")

    # Test Case 3: Disconnected Graph, Start 0
    v3 = 5
    adj3 = [[] for _ in range(v3)]
    edges3 = [(0, 1), (1, 0), (1, 2), (2, 1), (3, 4), (4, 3)]
    for u, v in edges3:
        adj3[u].append(v)
    print(f"Test Case 3 (Disconnected Graph, Start 0): {dfs(v3, adj3, 0)}")

    # Test Case 4: Line Graph, Start 2
    v4 = 5
    adj4 = [[] for _ in range(v4)]
    edges4 = [(0, 1), (1, 0), (1, 2), (2, 1), (2, 3), (3, 2), (3, 4), (4, 3)]
    for u, v in edges4:
        adj4[u].append(v)
    print(f"Test Case 4 (Line Graph, Start 2): {dfs(v4, adj4, 2)}")

    # Test Case 5: Single Node Graph, Start 0
    v5 = 1
    adj5 = [[] for _ in range(v5)]
    print(f"Test Case 5 (Single Node Graph, Start 0): {dfs(v5, adj5, 0)}")


if __name__ == "__main__":
    main()