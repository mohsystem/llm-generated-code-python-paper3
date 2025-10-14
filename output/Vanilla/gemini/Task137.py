# Product table implemented as a dictionary of dictionaries
product_table = {
    "Laptop": {"id": 101, "price": 1200.50, "quantity": 10},
    "Mouse": {"id": 102, "price": 25.00, "quantity": 150},
    "Keyboard": {"id": 103, "price": 75.99, "quantity": 80},
    "Monitor": {"id": 104, "price": 300.00, "quantity": 45},
    "USB Hub": {"id": 105, "price": 15.50, "quantity": 200}
}

def get_product_details(product_name):
    """
    Inquires the product table for a product's details by its name.
    
    Args:
        product_name: The name of the product to search for.
    
    Returns:
        A string with the product details or a "not found" message.
    """
    product = product_table.get(product_name)
    if product:
        return f"ID: {product['id']}, Name: {product_name}, Price: {product['price']:.2f}, Quantity: {product['quantity']}"
    else:
        return "Product not found."

if __name__ == "__main__":
    # 5 test cases
    test_cases = ["Laptop", "Monitor", "Mouse", "Webcam", "USB Hub"]

    print("--- Python Product Inquiry System ---")
    for test_case in test_cases:
        print(f"Querying for: {test_case}")
        details = get_product_details(test_case)
        print(f"Result: {details}\n")