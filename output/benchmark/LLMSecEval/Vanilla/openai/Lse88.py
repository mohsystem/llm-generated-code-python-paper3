# Entry point function: receives YAML payload as string and returns total price as string
def calculate_price(yaml_payload: str) -> str:
    product_code = None
    quantity = 0

    if yaml_payload is None:
        yaml_payload = ""

    for raw_line in yaml_payload.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.strip()
        value = value.strip()
        if key == "product_code":
            product_code = value
        elif key == "quantity":
            try:
                quantity = int(value)
            except ValueError:
                quantity = 0

    prices = {
        "P001": 10.0,
        "P002": 15.5,
        "P003": 7.25,
        "P004": 100.0,
        "P005": 0.99,
    }
    price = prices.get(product_code, 0.0)
    total = price * max(0, quantity)
    return f"{total:.2f}"


if __name__ == "__main__":
    tests = [
        "product_code: P001\nquantity: 3",
        "quantity: 2\nproduct_code: P002",
        "product_code: P003\nquantity: 4",
        "product_code: P999\nquantity: 1",
        "product_code: P005\nquantity: 5",
    ]
    for t in tests:
        print(calculate_price(t))