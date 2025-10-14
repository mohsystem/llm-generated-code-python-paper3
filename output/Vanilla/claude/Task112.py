
from pymongo import MongoClient
from bson.objectid import ObjectId

class Task112:
    def __init__(self, connection_string, db_name, collection_name):
        self.client = MongoClient(connection_string)
        self.database = self.client[db_name]
        self.collection = self.database[collection_name]

    def create(self, name, age, email):
        """Create operation"""
        doc = {
            "name": name,
            "age": age,
            "email": email
        }
        result = self.collection.insert_one(doc)
        return f"Created document with ID: {result.inserted_id}"

    def read(self, name):
        """Read operation"""
        doc = self.collection.find_one({"name": name})
        if doc:
            return f"Found: {doc}"
        return "Document not found"

    def update(self, name, new_age):
        """Update operation"""
        result = self.collection.update_one(
            {"name": name},
            {"$set": {"age": new_age}}
        )
        return f"Modified count: {result.modified_count}"

    def delete(self, name):
        """Delete operation"""
        result = self.collection.delete_one({"name": name})
        return f"Deleted count: {result.deleted_count}"

    def close(self):
        """Close the connection"""
        if self.client:
            self.client.close()


def main():
    # Note: Replace with your MongoDB connection string
    connection_string = "mongodb://localhost:27017"
    db_name = "testdb"
    collection_name = "users"

    mongo_ops = Task112(connection_string, db_name, collection_name)

    print("Test Case 1: Create a document")
    print(mongo_ops.create("John Doe", 30, "john@example.com"))

    print("\\nTest Case 2: Read a document")
    print(mongo_ops.read("John Doe"))

    print("\\nTest Case 3: Update a document")
    print(mongo_ops.update("John Doe", 31))

    print("\\nTest Case 4: Read updated document")
    print(mongo_ops.read("John Doe"))

    print("\\nTest Case 5: Delete a document")
    print(mongo_ops.delete("John Doe"))

    mongo_ops.close()


if __name__ == "__main__":
    main()
