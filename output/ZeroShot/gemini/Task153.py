import collections

def bfs(graph, start_node):
    """
    Performs a Breadth-First Search on a graph.

    :param graph: A dictionary representing the adjacency list of the graph.
    :param start_node: The node to start the BFS from.
    :return: A list of nodes in BFS traversal order, or an empty list if start_node is invalid.
    """
    # Input validation
    if graph is None or start_node not in graph:
        print(f"Error: Invalid input. Graph is None or start_node '{start_node}' not in graph.")
        return []

    visited = set()
    queue = collections.deque([start_node])
    visited.add(start_node)
    bfs_traversal = []

    while queue:
        node = queue.popleft()
        bfs_traversal.append(node)

        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)

    return bfs_traversal

def add_edge(graph, u, v):
    """Helper function to add an edge to an undirected graph."""
    graph.setdefault(u, []).append(v)
    graph.setdefault(v, []).append(u)

def main():
    """Main function with test cases."""
    # Graph representation: Adjacency list
    #      0 --- 1
    #      | \   |
    #      |  \  |
    #      2---3 4 --- 6
    #      |
    #      5
    graph = {}
    add_edge(graph, 0, 1)
    add_edge(graph, 0, 2)
    add_edge(graph, 0, 3)
    add_edge(graph, 1, 4)
    add_edge(graph, 2, 3)
    add_edge(graph, 2, 5)
    add_edge(graph, 4, 6)
    # Ensure all nodes are in the graph, even if they have no outgoing edges
    for i in range(7):
        graph.setdefault(i, [])

    # --- Test Cases ---
    test_starts = [0, 3, 5, 6, 99]  # 99 is an invalid node

    for i, start_node in enumerate(test_starts):
        print(f"Test Case {i + 1}: BFS starting from node {start_node}")
        result = bfs(graph, start_node)
        if not result and start_node not in graph:
             print(" -> Handled invalid start node correctly.")
        else:
            print(f" -> Traversal: {result}")
        print("--------------------")


if __name__ == "__main__":
    main()