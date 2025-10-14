from collections import deque

class Task153:
    @staticmethod
    def bfs(n, edges, start):
        if n <= 0 or start < 0 or start >= n:
            return []
        adj = [[] for _ in range(n)]
        if edges is not None:
            for u, v in edges:
                if 0 <= u < n and 0 <= v < n:
                    adj[u].append(v)
                    adj[v].append(u)
        for lst in adj:
            lst.sort()
        vis = [False] * n
        q = deque()
        order = []
        vis[start] = True
        q.append(start)
        while q:
            u = q.popleft()
            order.append(u)
            for v in adj[u]:
                if not vis[v]:
                    vis[v] = True
                    q.append(v)
        return order

def main():
    print(Task153.bfs(4, [(0, 1), (1, 2), (2, 3)], 0))      # [0, 1, 2, 3]
    print(Task153.bfs(5, [(3, 4), (0, 1)], 3))              # [3, 4]
    print(Task153.bfs(4, [(0, 1), (1, 2), (2, 0), (2, 3)], 1))  # [1, 0, 2, 3]
    print(Task153.bfs(6, [(0,1),(1,2),(2,3),(3,0),(0,2),(4,5)], 2))  # [2, 0, 1, 3]
    print(Task153.bfs(1, [], 0))                            # [0]

if __name__ == "__main__":
    main()