
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from bson.objectid import ObjectId

class Task112:
    def __init__(self):
        self.connection_string = "mongodb://localhost:27017"
        self.database_name = "testdb"
        self.collection_name = "users"
        
        try:
            self.client = MongoClient(self.connection_string)
            self.database = self.client[self.database_name]
            self.collection = self.database[self.collection_name]
        except PyMongoError as e:
            print(f"Error connecting to MongoDB: {e}")
            self.client = None
    
    # Create operation
    def create_document(self, name, email, age):
        try:
            doc = {
                "name": name,
                "email": email,
                "age": age
            }
            result = self.collection.insert_one(doc)
            return str(result.inserted_id)
        except PyMongoError as e:
            print(f"Error creating document: {e}")
            return None
    
    # Read operation
    def read_document(self, doc_id):
        try:
            object_id = ObjectId(doc_id)
            document = self.collection.find_one({"_id": object_id})
            return document
        except Exception as e:
            print(f"Error reading document: {e}")
            return None
    
    # Update operation
    def update_document(self, doc_id, name=None, email=None, age=None):
        try:
            object_id = ObjectId(doc_id)
            update_fields = {}
            if name is not None:
                update_fields["name"] = name
            if email is not None:
                update_fields["email"] = email
            if age is not None and age > 0:
                update_fields["age"] = age
            
            self.collection.update_one(
                {"_id": object_id},
                {"$set": update_fields}
            )
            return True
        except Exception as e:
            print(f"Error updating document: {e}")
            return False
    
    # Delete operation
    def delete_document(self, doc_id):
        try:
            object_id = ObjectId(doc_id)
            self.collection.delete_one({"_id": object_id})
            return True
        except Exception as e:
            print(f"Error deleting document: {e}")
            return False
    
    def close(self):
        if self.client:
            self.client.close()


def main():
    task = Task112()
    
    print("=== Test Case 1: Create Document ===")
    id1 = task.create_document("John Doe", "john@example.com", 30)
    print(f"Created document with ID: {id1}")
    
    print("\\n=== Test Case 2: Read Document ===")
    if id1:
        doc = task.read_document(id1)
        print(f"Retrieved document: {doc}")
    
    print("\\n=== Test Case 3: Create Multiple Documents ===")
    id2 = task.create_document("Jane Smith", "jane@example.com", 25)
    id3 = task.create_document("Bob Johnson", "bob@example.com", 35)
    print(f"Created documents with IDs: {id2}, {id3}")
    
    print("\\n=== Test Case 4: Update Document ===")
    if id1:
        updated = task.update_document(id1, name="John Updated", age=31)
        print(f"Update successful: {updated}")
        updated_doc = task.read_document(id1)
        print(f"Updated document: {updated_doc}")
    
    print("\\n=== Test Case 5: Delete Document ===")
    if id1:
        deleted = task.delete_document(id1)
        print(f"Delete successful: {deleted}")
        deleted_doc = task.read_document(id1)
        print(f"Document after deletion: {deleted_doc}")
    
    task.close()


if __name__ == "__main__":
    main()
