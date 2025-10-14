
from typing import Optional, Dict, Any
import re
import os
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from bson.objectid import ObjectId
from bson.errors import InvalidId


class Task112:
    VALID_DB_NAME = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')
    VALID_COLLECTION_NAME = re.compile(r'^[a-zA-Z0-9_-]{1,255}$')
    MAX_STRING_LENGTH = 10000

    def __init__(self, connection_string: str, database_name: str, collection_name: str):
        if not connection_string or not connection_string.strip():
            raise ValueError("Connection string cannot be null or empty")
        if not self._is_valid_database_name(database_name):
            raise ValueError("Invalid database name")
        if not self._is_valid_collection_name(collection_name):
            raise ValueError("Invalid collection name")

        try:
            self.client = MongoClient(connection_string)
            self.database = self.client[database_name]
            self.collection = self.database[collection_name]
        except PyMongoError as e:
            raise RuntimeError(f"Failed to connect to MongoDB: {str(e)}")

    def _is_valid_database_name(self, name: str) -> bool:
        return name is not None and self.VALID_DB_NAME.match(name) is not None

    def _is_valid_collection_name(self, name: str) -> bool:
        return name is not None and self.VALID_COLLECTION_NAME.match(name) is not None

    def _validate_string(self, input_str: str, field_name: str) -> str:
        if input_str is None:
            raise ValueError(f"{field_name} cannot be null")
        if not isinstance(input_str, str):
            raise ValueError(f"{field_name} must be a string")
        if len(input_str) > self.MAX_STRING_LENGTH:
            raise ValueError(f"{field_name} exceeds maximum length")
        return input_str

    def _validate_positive_int(self, value: int, field_name: str) -> int:
        if not isinstance(value, int):
            raise ValueError(f"{field_name} must be an integer")
        if value < 0:
            raise ValueError(f"{field_name} must be non-negative")
        return value

    def create_document(self, name: str, email: str, age: int) -> str:
        try:
            self._validate_string(name, "Name")
            self._validate_string(email, "Email")
            self._validate_positive_int(age, "Age")

            if age > 150:
                raise ValueError("Age must be realistic")

            doc = {
                "name": name,
                "email": email,
                "age": age
            }

            result = self.collection.insert_one(doc)
            return str(result.inserted_id)
        except ValueError as e:
            raise e
        except PyMongoError as e:
            raise RuntimeError(f"Failed to create document: {str(e)}")

    def read_document(self, doc_id: str) -> Optional[Dict[str, Any]]:
        try:
            self._validate_string(doc_id, "ID")
            
            try:
                object_id = ObjectId(doc_id)
            except InvalidId:
                raise ValueError("Invalid ObjectId format")

            doc = self.collection.find_one({"_id": object_id})
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except ValueError as e:
            raise e
        except PyMongoError as e:
            raise RuntimeError(f"Failed to read document: {str(e)}")

    def update_document(self, doc_id: str, name: str, email: str, age: int) -> bool:
        try:
            self._validate_string(doc_id, "ID")
            
            try:
                object_id = ObjectId(doc_id)
            except InvalidId:
                raise ValueError("Invalid ObjectId format")

            self._validate_string(name, "Name")
            self._validate_string(email, "Email")
            self._validate_positive_int(age, "Age")

            if age > 150:
                raise ValueError("Age must be realistic")

            update_doc = {
                "$set": {
                    "name": name,
                    "email": email,
                    "age": age
                }
            }

            result = self.collection.update_one({"_id": object_id}, update_doc)
            return result.modified_count > 0
        except ValueError as e:
            raise e
        except PyMongoError as e:
            raise RuntimeError(f"Failed to update document: {str(e)}")

    def delete_document(self, doc_id: str) -> bool:
        try:
            self._validate_string(doc_id, "ID")
            
            try:
                object_id = ObjectId(doc_id)
            except InvalidId:
                raise ValueError("Invalid ObjectId format")

            result = self.collection.delete_one({"_id": object_id})
            return result.deleted_count > 0
        except ValueError as e:
            raise e
        except PyMongoError as e:
            raise RuntimeError(f"Failed to delete document: {str(e)}")

    def close(self):
        if self.client:
            self.client.close()


def main():
    connection_string = os.environ.get("MONGODB_URI")
    if not connection_string or not connection_string.strip():
        connection_string = "mongodb://localhost:27017"

    mongo_ops = None
    try:
        mongo_ops = Task112(connection_string, "testdb", "users")

        print("Test 1: Create document")
        id1 = mongo_ops.create_document("Alice Smith", "alice@example.com", 30)
        print(f"Created document with ID: {id1}")

        print("\\nTest 2: Read document")
        doc = mongo_ops.read_document(id1)
        print(f"Read document: {doc}")

        print("\\nTest 3: Update document")
        updated = mongo_ops.update_document(id1, "Alice Johnson", "alice.j@example.com", 31)
        print(f"Update successful: {updated}")

        print("\\nTest 4: Create multiple documents")
        id2 = mongo_ops.create_document("Bob Brown", "bob@example.com", 25)
        id3 = mongo_ops.create_document("Charlie Davis", "charlie@example.com", 35)
        print(f"Created documents with IDs: {id2}, {id3}")

        print("\\nTest 5: Delete document")
        deleted = mongo_ops.delete_document(id1)
        print(f"Delete successful: {deleted}")

        mongo_ops.delete_document(id2)
        mongo_ops.delete_document(id3)

    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        if mongo_ops:
            mongo_ops.close()


if __name__ == "__main__":
    main()
