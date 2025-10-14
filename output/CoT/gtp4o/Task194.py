# Chain-of-Through process:
# 1) Problem understanding: Find a secret 6-letter word via controlled queries to Master.guess within an allowed guess limit.
# 2) Security: Validate inputs, no external I/O dependency, safe operations, predictable behavior.
# 3) Secure coding: Encapsulate Master, avoid mutable shared global state, and handle edge cases.
# 4) Review: Deterministic minimax strategy, bounded loops, and no unsafe operations.
# 5) Output: Return specified message only.

from typing import List

class _Master:
    def __init__(self, words: List[str], secret: str, allowed: int):
        if secret not in words:
            raise ValueError("Secret must be in words")
        self._dict = set(words)
        self._secret = secret
        self._allowed = max(0, int(allowed))
        self._calls = 0
        self._success = False

    def guess(self, word: str) -> int:
        if not isinstance(word, str) or len(word) != 6 or word not in self._dict:
            return -1
        self._calls += 1
        m = sum(1 for a, b in zip(self._secret, word) if a == b)
        if m == 6:
            self._success = True
        return m

    def result_message(self) -> str:
        if self._success and self._calls <= self._allowed:
            return "You guessed the secret word correctly."
        return "Either you took too many guesses, or you did not find the secret word."

def _match(a: str, b: str) -> int:
    return sum(1 for x, y in zip(a, b) if x == y)

def _choose_guess(cands: List[str]) -> str:
    best = cands[0]
    best_score = 10**9
    for w in cands:
        bucket = [0]*7
        for v in cands:
            bucket[_match(w, v)] += 1
        worst = max(bucket)
        if worst < best_score:
            best_score = worst
            best = w
    return best

def solve(words: List[str], secret: str, allowedGuesses: int) -> str:
    if not isinstance(words, list) or not isinstance(secret, str) or len(secret) != 6:
        return "Either you took too many guesses, or you did not find the secret word."
    wl = [w for w in words if isinstance(w, str) and len(w) == 6]
    try:
        master = _Master(wl, secret, allowedGuesses)
    except Exception:
        return "Either you took too many guesses, or you did not find the secret word."
    cands = wl[:]
    guesses = 0
    while guesses < allowedGuesses and cands:
        g = _choose_guess(cands)
        res = master.guess(g)
        guesses += 1
        if res == 6:
            break
        cands = [w for w in cands if _match(w, g) == res]
    return master.result_message()

if __name__ == "__main__":
    tests = [
        (["acckzz","ccbazz","eiowzz","abcczz"], "acckzz", 10),
        (["hamada","khaled"], "hamada", 10),
        (["bbbbbb"], "bbbbbb", 1),
        (["kitten","kittey","bitten","sitten","mitten","kittzz"], "mitten", 10),
        (["acbdef","ghijkl","monkey","abcdef","zzzzzz","qwerty","yellow","hammer","flower","planet"], "flower", 20),
    ]
    for w, s, a in tests:
        print(solve(w, s, a))