class Master:
    def __init__(self, words, secret, allowed_guesses):
        self.wordset = set(words)
        self.secret = secret
        self.allowed = allowed_guesses
        self.calls = 0
        self.found = False

    def guess(self, word: str) -> int:
        if word not in self.wordset:
            return -1
        self.calls += 1
        m = sum(1 for a, b in zip(word, self.secret) if a == b)
        if m == 6:
            self.found = True
        return m

def _matches(a: str, b: str) -> int:
    return sum(1 for x, y in zip(a, b) if x == y)

def _pick_best(candidates):
    n = len(candidates)
    best_idx = 0
    best_worst = 10**9
    for i in range(n):
        wi = candidates[i]
        buckets = [0]*7
        for j in range(n):
            buckets[_matches(wi, candidates[j])] += 1
        worst = max(buckets)
        if worst < best_worst:
            best_worst = worst
            best_idx = i
    return candidates[best_idx]

def guessSecret(words, secret, allowedGuesses):
    master = Master(words, secret, allowedGuesses)
    candidates = list(words)
    while candidates and not master.found and master.calls < master.allowed:
        g = _pick_best(candidates)
        res = master.guess(g)
        if res == 6:
            break
        next_list = [w for w in candidates if _matches(w, g) == res and w != g]
        candidates = next_list
    if master.found and master.calls <= master.allowed:
        return "You guessed the secret word correctly."
    else:
        return "Either you took too many guesses, or you did not find the secret word."

if __name__ == "__main__":
    # Test case 1
    words1 = ["acckzz","ccbazz","eiowzz","abcczz"]
    print(guessSecret(words1, "acckzz", 10))
    # Test case 2
    words2 = ["hamada","khaled"]
    print(guessSecret(words2, "hamada", 10))
    # Test case 3
    words3 = ["python","typhon","thynop","cython","pebble","little","button","people","planet","plenty"]
    print(guessSecret(words3, "python", 10))
    # Test case 4
    words4 = ["planet","planer","planed","planes","platen","palnet","placet","planar"]
    print(guessSecret(words4, "planet", 10))
    # Test case 5
    words5 = ["silver","salver","sliver","sailor","slider","silken","sinker","sifter","sinner","single"]
    print(guessSecret(words5, "silver", 10))