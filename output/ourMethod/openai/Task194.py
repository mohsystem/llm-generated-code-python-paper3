from typing import List, Dict

SUCCESS_MSG = "You guessed the secret word correctly."
FAILURE_MSG = "Either you took too many guesses, or you did not find the secret word."

class Master:
    def __init__(self, words: List[str], secret: str, allowed_guesses: int) -> None:
        self.word_set = set(w for w in words if isinstance(w, str) and len(w) == 6)
        self.secret = secret
        self.allowed = max(0, int(allowed_guesses))
        self.guess_count = 0
        self.guessed = False

    def guess(self, word: str) -> int:
        self.guess_count += 1
        if not isinstance(word, str) or len(word) != 6 or word not in self.word_set:
            return -1
        matches = sum(1 for i in range(6) if word[i] == self.secret[i])
        if matches == 6:
            self.guessed = True
        return matches

    def result_message(self) -> str:
        if self.guessed and self.guess_count <= self.allowed:
            return SUCCESS_MSG
        return FAILURE_MSG

def match_count(a: str, b: str) -> int:
    return sum(1 for i in range(6) if a[i] == b[i])

def solve(words: List[str], secret: str, allowed_guesses: int) -> str:
    if not isinstance(secret, str) or len(secret) != 6 or not isinstance(words, list):
        return FAILURE_MSG
    master = Master(words, secret, allowed_guesses)
    candidates = [i for i, w in enumerate(words) if isinstance(w, str) and len(w) == 6]

    while candidates and master.guess_count < allowed_guesses:
        best_idx = -1
        best_score = 10**9
        best_word = None

        for idx in candidates:
            w = words[idx]
            buckets = [0] * 7
            for jdx in candidates:
                v = words[jdx]
                buckets[match_count(w, v)] += 1
            worst = max(buckets)
            if worst < best_score or (worst == best_score and (best_word is None or w < best_word)):
                best_score = worst
                best_idx = idx
                best_word = w

        if best_idx == -1:
            break

        guess_word = words[best_idx]
        res = master.guess(guess_word)
        if res == 6:
            break
        if res < 0:
            candidates = [idx for idx in candidates if idx != best_idx]
            continue
        candidates = [idx for idx in candidates if match_count(words[idx], guess_word) == res]

    return master.result_message()

def main() -> None:
    tests = [
        (["acckzz", "ccbazz", "eiowzz", "abcczz"], "acckzz", 10),
        (["hamada", "khaled"], "hamada", 10),
        (["aaaaaa", "bbbbbb", "cccccc", "dddddd", "eeffee", "ffeeee", "fedcba", "abcdef"], "abcdef", 10),
        (["absdef", "abqdef", "abzdef", "abzcef", "abzcdx", "abzcdz", "abzcdy", "abztdy", "qbztdy", "xyzabc"], "abzcdz", 10),
        (["nearer", "bearer", "hearer", "seared", "neared", "dealer", "leader", "linear"], "neared", 12),
    ]
    for words, secret, allowed in tests:
        print(solve(words, secret, allowed))

if __name__ == "__main__":
    main()