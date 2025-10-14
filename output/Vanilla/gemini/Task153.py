import collections

def bfs(graph, start_node):
    """
    Performs a Breadth-First Search on a graph.

    Args:
      graph: A dictionary representing the adjacency list of the graph.
      start_node: The node to start the BFS from.

    Returns:
      A list of nodes in the order they were visited.
    """
    if start_node not in graph:
        return []

    visited = set()
    queue = collections.deque([start_node])
    visited.add(start_node)
    traversal_order = []

    while queue:
        node = queue.popleft()
        traversal_order.append(node)

        # Use .get() to handle nodes with no neighbors gracefully
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)

    return traversal_order

def main():
    # Helper to build graph for tests
    def build_graph(edges, num_nodes):
        graph = {i: [] for i in range(num_nodes)}
        for u, v in edges:
            graph[u].append(v)
            graph[v].append(u)
        return graph

    # Test Case 1: Connected graph
    print("--- Test Case 1 ---")
    edges1 = [(0, 1), (0, 2), (1, 3), (2, 4)]
    graph1 = build_graph(edges1, 5)
    print("Graph: Connected graph with 5 vertices.")
    print(f"BFS starting from node 0: {bfs(graph1, 0)}")

    # Test Case 2: Different start node on a more complex graph
    print("\n--- Test Case 2 ---")
    edges2 = [(0, 1), (0, 2), (1, 2), (1, 3), (2, 4)]
    graph2 = build_graph(edges2, 5)
    print("Graph: More complex connected graph.")
    print(f"BFS starting from node 3: {bfs(graph2, 3)}")
    
    # Test Case 3: Disconnected graph
    print("\n--- Test Case 3 ---")
    edges3 = [(0, 1), (0, 2), (3, 4), (5, 6)]
    graph3 = build_graph(edges3, 7)
    print("Graph: Disconnected graph with 7 vertices.")
    print(f"BFS starting from node 3: {bfs(graph3, 3)}")

    # Test Case 4: Single node graph
    print("\n--- Test Case 4 ---")
    graph4 = {0: []}
    print("Graph: Single node graph.")
    print(f"BFS starting from node 0: {bfs(graph4, 0)}")

    # Test Case 5: Linear graph
    print("\n--- Test Case 5 ---")
    edges5 = [(0, 1), (1, 2), (2, 3), (3, 4)]
    graph5 = build_graph(edges5, 5)
    print("Graph: Linear graph with 5 vertices.")
    print(f"BFS starting from node 2: {bfs(graph5, 2)}")

if __name__ == "__main__":
    main()