
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, PyMongoError
from bson.objectid import ObjectId
import re
import sys

class Task112:
    def __init__(self, connection_string, db_name, collection_name):
        """Initialize MongoDB connection with secure practices"""
        try:
            # Secure connection with authentication support
            self.client = MongoClient(
                connection_string,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000
            )
            # Test connection
            self.client.admin.command('ping')
            self.db = self.client[db_name]
            self.collection = self.db[collection_name]
        except ConnectionFailure as e:
            print(f"Failed to connect to MongoDB: {e}", file=sys.stderr)
            raise
        except Exception as e:
            print(f"Error initializing MongoDB: {e}", file=sys.stderr)
            raise
    
    def _validate_email(self, email):
        """Validate email format"""
        pattern = r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$'
        return re.match(pattern, email) is not None
    
    def create_document(self, name, age, email):
        """CREATE operation with input validation"""
        try:
            # Input validation
            if not name or not name.strip():
                raise ValueError("Name cannot be null or empty")
            if not isinstance(age, int) or age < 0 or age > 150:
                raise ValueError("Age must be between 0 and 150")
            if not email or not self._validate_email(email):
                raise ValueError("Invalid email format")
            
            document = {
                "name": name.strip(),
                "age": age,
                "email": email.strip(),
                "createdAt": __import__('time').time()
            }
            
            result = self.collection.insert_one(document)
            return str(result.inserted_id)
        except ValueError as e:
            print(f"Validation error: {e}", file=sys.stderr)
            return None
        except PyMongoError as e:
            print(f"Error creating document: {e}", file=sys.stderr)
            return None
    
    def read_document(self, doc_id):
        """READ operation with safe query"""
        try:
            # Validate ObjectId format
            if not ObjectId.is_valid(doc_id):
                raise ValueError("Invalid ObjectId format")
            
            return self.collection.find_one({"_id": ObjectId(doc_id)})
        except ValueError as e:
            print(f"Validation error: {e}", file=sys.stderr)
            return None
        except PyMongoError as e:
            print(f"Error reading document: {e}", file=sys.stderr)
            return None
    
    def read_all_documents(self):
        """READ ALL operation"""
        try:
            documents = list(self.collection.find())
            for doc in documents:
                print(doc)
            return documents
        except PyMongoError as e:
            print(f"Error reading all documents: {e}", file=sys.stderr)
            return []
    
    def update_document(self, doc_id, name=None, age=None, email=None):
        """UPDATE operation with input validation"""
        try:
            # Validate ObjectId format
            if not ObjectId.is_valid(doc_id):
                raise ValueError("Invalid ObjectId format")
            
            # Input validation
            update_data = {}
            if name is not None:
                if not name.strip():
                    raise ValueError("Name cannot be empty")
                update_data["name"] = name.strip()
            
            if age is not None:
                if not isinstance(age, int) or age < 0 or age > 150:
                    raise ValueError("Age must be between 0 and 150")
                update_data["age"] = age
            
            if email is not None:
                if not self._validate_email(email):
                    raise ValueError("Invalid email format")
                update_data["email"] = email.strip()
            
            if not update_data:
                return False
            
            update_data["updatedAt"] = __import__('time').time()
            
            result = self.collection.update_one(
                {"_id": ObjectId(doc_id)},
                {"$set": update_data}
            )
            
            return result.modified_count > 0
        except ValueError as e:
            print(f"Validation error: {e}", file=sys.stderr)
            return False
        except PyMongoError as e:
            print(f"Error updating document: {e}", file=sys.stderr)
            return False
    
    def delete_document(self, doc_id):
        """DELETE operation with validation"""
        try:
            # Validate ObjectId format
            if not ObjectId.is_valid(doc_id):
                raise ValueError("Invalid ObjectId format")
            
            result = self.collection.delete_one({"_id": ObjectId(doc_id)})
            return result.deleted_count > 0
        except ValueError as e:
            print(f"Validation error: {e}", file=sys.stderr)
            return False
        except PyMongoError as e:
            print(f"Error deleting document: {e}", file=sys.stderr)
            return False
    
    def close(self):
        """Close MongoDB connection securely"""
        if self.client:
            self.client.close()

def main():
    # Use secure connection string with authentication
    connection_string = "mongodb://localhost:27017/"
    db_name = "testdb"
    collection_name = "users"
    
    mongo_ops = Task112(connection_string, db_name, collection_name)
    
    try:
        print("=== Test Case 1: Create Documents ===")
        id1 = mongo_ops.create_document("John Doe", 30, "john@example.com")
        print(f"Created document with ID: {id1}")
        
        id2 = mongo_ops.create_document("Jane Smith", 25, "jane@example.com")
        print(f"Created document with ID: {id2}")
        
        print("\\n=== Test Case 2: Read Document ===")
        doc = mongo_ops.read_document(id1)
        if doc:
            print(f"Read document: {doc}")
        
        print("\\n=== Test Case 3: Read All Documents ===")
        mongo_ops.read_all_documents()
        
        print("\\n=== Test Case 4: Update Document ===")
        updated = mongo_ops.update_document(id1, "John Updated", 31, "johnupdated@example.com")
        print(f"Update successful: {updated}")
        
        print("\\n=== Test Case 5: Delete Document ===")
        deleted = mongo_ops.delete_document(id2)
        print(f"Delete successful: {deleted}")
        
        print("\\n=== Final State ===")
        mongo_ops.read_all_documents()
        
    except Exception as e:
        print(f"Error in main: {e}", file=sys.stderr)
    finally:
        mongo_ops.close()

if __name__ == "__main__":
    main()
