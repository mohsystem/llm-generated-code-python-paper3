from typing import List, Set

class Master:
    def __init__(self, words: List[str], secret: str, allowed: int):
        if not words or not secret:
            raise ValueError("Invalid inputs")
        self.word_set: Set[str] = set(words)
        if secret not in self.word_set:
            raise ValueError("Secret not in word list")
        self.secret = secret
        self.allowed = allowed
        self.calls = 0

    def guess(self, word: str) -> int:
        self.calls += 1
        if word not in self.word_set:
            return -1
        return match_count(word, self.secret)

def match_count(a: str, b: str) -> int:
    if a is None or b is None or len(a) != len(b):
        return -1
    return sum(1 for x, y in zip(a, b) if x == y)

def choose_best_guess(candidates: List[str]) -> str:
    best = candidates[0]
    best_zero = 10**9
    n = len(candidates)
    for i in range(n):
        wi = candidates[i]
        zeros = 0
        for j in range(n):
            if i == j:
                continue
            if match_count(wi, candidates[j]) == 0:
                zeros += 1
        if zeros < best_zero:
            best_zero = zeros
            best = wi
    return best

def find_secret_word(words: List[str], master: Master) -> bool:
    candidates = list(words)
    while candidates and master.calls < master.allowed:
        guess = choose_best_guess(candidates)
        res = master.guess(guess)
        if res == 6:
            return True
        if res < 0:
            return False
        next_cands = [w for w in candidates if match_count(w, guess) == res]
        candidates = next_cands
        if len(candidates) == 1 and master.calls < master.allowed:
            return master.guess(candidates[0]) == 6
    return False

def solve_test_case(secret: str, words: List[str], allowed_guesses: int) -> str:
    words = [w for w in words if isinstance(w, str) and len(w) == 6]
    master = Master(words, secret, allowed_guesses)
    guessed = find_secret_word(words, master)
    if guessed and master.calls <= allowed_guesses:
        return "You guessed the secret word correctly."
    else:
        return "Either you took too many guesses, or you did not find the secret word."

if __name__ == "__main__":
    # Test case 1
    print(solve_test_case("acckzz", ["acckzz","ccbazz","eiowzz","abcczz"], 10))
    # Test case 2
    print(solve_test_case("hamada", ["hamada","khaled"], 10))
    # Test case 3
    print(solve_test_case("sprite", ["spiral","sprint","sprout","sprite","spirit","spring"], 10))
    # Test case 4
    print(solve_test_case("zenith", ["abacus","absurd","acumen","agenda","zenith","shrimp","zigzag","little","letter","legend"], 15))
    # Test case 5
    print(solve_test_case("orange", ["orange","banana","tomato","pepper","potato","carrot","onions","radish","celery","garlic"], 12))