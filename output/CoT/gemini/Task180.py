import collections

def reparent_tree(original_adj, new_root):
    """
    Reparents a tree on a selected node.

    :param original_adj: The original undirected tree represented as an adjacency list (dict).
    :param new_root: The node to become the new root.
    :return: A new directed tree (dict) rooted at new_root.
    """
    if new_root not in original_adj:
        return {}

    new_adj = {node: [] for node in original_adj}

    def build_new_tree_recursive(current_node, parent_node):
        if current_node not in original_adj:
            return
        for neighbor in original_adj[current_node]:
            if neighbor != parent_node:
                new_adj[current_node].append(neighbor)
                build_new_tree_recursive(neighbor, current_node)

    build_new_tree_recursive(new_root, -1)
    
    # Sort children for consistent output and sort keys for printing
    for children in new_adj.values():
        children.sort()
        
    return collections.OrderedDict(sorted(new_adj.items()))

def build_graph_from_edges(edges):
    """Helper to build an undirected graph from a list of edges."""
    adj = collections.defaultdict(list)
    nodes = set()
    for u, v in edges:
        nodes.add(u)
        nodes.add(v)
    
    # Initialize all nodes to handle disconnected components or single nodes
    for node in nodes:
        adj[node] = []
        
    for u, v in edges:
        adj[u].append(v)
        adj[v].append(u)
    return dict(adj)

if __name__ == "__main__":
    # Test Case 1: Example from prompt
    edges1 = [(0, 1), (0, 2), (0, 3), (1, 4), (1, 5), (2, 6), (2, 7), (3, 8), (3, 9)]
    new_root1 = 6
    graph1 = build_graph_from_edges(edges1)
    print(f"Test Case 1: Reparent on {new_root1}")
    print(f"Original Tree: {collections.OrderedDict(sorted(graph1.items()))}")
    print(f"Reparented Tree: {reparent_tree(graph1, new_root1)}\n")

    # Test Case 2: Line graph
    edges2 = [(0, 1), (1, 2), (2, 3), (3, 4)]
    new_root2 = 2
    graph2 = build_graph_from_edges(edges2)
    print(f"Test Case 2: Reparent on {new_root2}")
    print(f"Original Tree: {collections.OrderedDict(sorted(graph2.items()))}")
    print(f"Reparented Tree: {reparent_tree(graph2, new_root2)}\n")

    # Test Case 3: Root is already the 'natural' root
    new_root3 = 0
    print(f"Test Case 3: Reparent on {new_root3}")
    print(f"Original Tree: {collections.OrderedDict(sorted(graph1.items()))}")
    print(f"Reparented Tree: {reparent_tree(graph1, new_root3)}\n")

    # Test Case 4: Leaf node as new root
    new_root4 = 9
    print(f"Test Case 4: Reparent on {new_root4}")
    print(f"Original Tree: {collections.OrderedDict(sorted(graph1.items()))}")
    print(f"Reparented Tree: {reparent_tree(graph1, new_root4)}\n")

    # Test Case 5: Small tree
    edges5 = [(1, 0), (0, 2)]
    new_root5 = 1
    graph5 = build_graph_from_edges(edges5)
    print(f"Test Case 5: Reparent on {new_root5}")
    print(f"Original Tree: {collections.OrderedDict(sorted(graph5.items()))}")
    print(f"Reparented Tree: {reparent_tree(graph5, new_root5)}\n")