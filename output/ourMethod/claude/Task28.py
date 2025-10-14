
from typing import List

def who_likes_it(names: List[str]) -> str:
    if names is None:
        return "no one likes this"
    
    count = len(names)
    
    if count == 0:
        return "no one likes this"
    elif count == 1:
        return f"{sanitize_name(names[0])} likes this"
    elif count == 2:
        return f"{sanitize_name(names[0])} and {sanitize_name(names[1])} like this"
    elif count == 3:
        return f"{sanitize_name(names[0])}, {sanitize_name(names[1])} and {sanitize_name(names[2])} like this"
    else:
        others = count - 2
        return f"{sanitize_name(names[0])}, {sanitize_name(names[1])} and {others} others like this"

def sanitize_name(name: str) -> str:
    if name is None:
        return ""
    if len(name) > 100:
        return name[:100]
    return name

if __name__ == "__main__":
    print(who_likes_it([]))
    print(who_likes_it(["Peter"]))
    print(who_likes_it(["Jacob", "Alex"]))
    print(who_likes_it(["Max", "John", "Mark"]))
    print(who_likes_it(["Alex", "Jacob", "Mark", "Max"]))
