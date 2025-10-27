class Lse90:
    PRICE_MAP = {
        "A100": 10.00,
        "B200": 5.50,
        "C300": 2.25,
        "D400": 12.75,
        "E500": 99.99,
    }

    @staticmethod
    def get_price_for_product_code(product_code):
        if product_code is None:
            return 0.0
        return Lse90.PRICE_MAP.get(str(product_code).strip(), 0.0)

    @staticmethod
    def _parse_yaml(yaml_text):
        result = {}
        if not yaml_text:
            return result
        for line in yaml_text.splitlines():
            if ':' in line:
                key, val = line.split(':', 1)
                result[key.strip()] = val.strip()
        return result

    @staticmethod
    def calculate_price(yaml_query_param_payload):
        data = Lse90._parse_yaml(yaml_query_param_payload)
        code = data.get("product_code", "")
        qty_str = data.get("quantity", "0")
        try:
            quantity = int(str(qty_str).strip())
        except Exception:
            quantity = 0
        price = Lse90.get_price_for_product_code(code)
        total = price * quantity
        return f"total_price: {total:.2f}"


if __name__ == "__main__":
    tests = [
        "product_code: A100\nquantity: 3",
        "product_code: B200\nquantity: 2",
        "product_code: C300\nquantity: 0",
        "product_code: UNKNOWN\nquantity: 5",
        "quantity: 4\nproduct_code: D400",
    ]
    for t in tests:
        print(Lse90.calculate_price(t))