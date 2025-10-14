
class Product:
    def __init__(self, id, name, price, category, stock):
        self.id = id
        self.name = name
        self.price = price
        self.category = category
        self.stock = stock
    
    def __str__(self):
        return f"ID: {self.id}, Name: {self.name}, Price: ${self.price:.2f}, Category: {self.category}, Stock: {self.stock}"

product_table = {
    "P001": Product("P001", "Laptop", 999.99, "Electronics", 50),
    "P002": Product("P002", "Mouse", 29.99, "Electronics", 200),
    "P003": Product("P003", "Keyboard", 79.99, "Electronics", 150),
    "P004": Product("P004", "Monitor", 299.99, "Electronics", 75),
    "P005": Product("P005", "Desk Chair", 199.99, "Furniture", 30)
}

def query_product(product_id):
    return product_table.get(product_id)

def query_products_by_category(category):
    results = []
    for product in product_table.values():
        if product.category.lower() == category.lower():
            results.append(product)
    return results

def query_products_by_price_range(min_price, max_price):
    results = []
    for product in product_table.values():
        if min_price <= product.price <= max_price:
            results.append(product)
    return results

if __name__ == "__main__":
    print("Test Case 1: Query by Product ID")
    product1 = query_product("P001")
    print(product1 if product1 else "Product not found")
    print()
    
    print("Test Case 2: Query by Product ID (Non-existent)")
    product2 = query_product("P999")
    print(product2 if product2 else "Product not found")
    print()
    
    print("Test Case 3: Query by Category")
    electronics = query_products_by_category("Electronics")
    print(f"Electronics products: {len(electronics)}")
    for p in electronics:
        print(p)
    print()
    
    print("Test Case 4: Query by Price Range (50-100)")
    mid_range = query_products_by_price_range(50.0, 100.0)
    print(f"Products in range: {len(mid_range)}")
    for p in mid_range:
        print(p)
    print()
    
    print("Test Case 5: Query by Category (Furniture)")
    furniture = query_products_by_category("Furniture")
    print(f"Furniture products: {len(furniture)}")
    for p in furniture:
        print(p)
