import json

PRODUCT_TABLE = [
    {"id": 1001, "name": "Widget", "category": "Tools", "price": 19.99, "stock": 120},
    {"id": 1002, "name": "Gadget", "category": "Electronics", "price": 99.50, "stock": 55},
    {"id": 1003, "name": "Gizmo", "category": "Electronics", "price": 49.00, "stock": 200},
    {"id": 1004, "name": "Pro Headphones", "category": "Audio", "price": 129.99, "stock": 35},
    {"id": 1005, "name": "Office Chair", "category": "Furniture", "price": 199.99, "stock": 15},
    {"id": 1006, "name": "Pro Keyboard", "category": "Computers", "price": 89.99, "stock": 60},
]

def process_input(user_input: str) -> str:
    if user_input is None:
        return "[]"
    s = user_input.strip()
    if not s:
        return "[]"

    if s.lower() == "all":
        return json.dumps(PRODUCT_TABLE, ensure_ascii=False)

    if "=" in s:
        key, value = s.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "id":
            try:
                id_val = int(value)
                res = [p for p in PRODUCT_TABLE if p["id"] == id_val]
                return json.dumps(res, ensure_ascii=False)
            except ValueError:
                return "[]"
        elif key == "name":
            res = [p for p in PRODUCT_TABLE if p["name"].lower() == value.lower()]
            return json.dumps(res, ensure_ascii=False)
        elif key == "category":
            res = [p for p in PRODUCT_TABLE if p["category"].lower() == value.lower()]
            return json.dumps(res, ensure_ascii=False)
        elif key == "search":
            v = value.lower()
            res = [p for p in PRODUCT_TABLE if v in p["name"].lower()]
            return json.dumps(res, ensure_ascii=False)

    return "[]"

if __name__ == "__main__":
    tests = ["id=1002", "name=Gizmo", "category=Audio", "search=Pro", "all"]
    for t in tests:
        print("Query:", t)
        print(process_input(t))