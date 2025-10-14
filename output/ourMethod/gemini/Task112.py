# To run this script, you need to install the pymongo library:
# pip install pymongo
#
# Also ensure that a MongoDB instance is running on localhost:27017.

import os
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import PyMongoError
from typing import Dict, Any, Optional

# NOTE: For a production environment, the connection string should not be hardcoded.
# It should be loaded from a secure configuration source or environment variables.
# Example: URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
URI = "mongodb://localhost:27017/"
DATABASE_NAME = "my_python_db"
COLLECTION_NAME = "users"

def create_user(collection: Collection, name: str, email: str) -> Optional[str]:
    """
    Creates a new document in the specified collection.
    :param collection: The MongoDB collection.
    :param name: The name of the user.
    :param email: The email of the user.
    :return: The ObjectId of the inserted document as a hex string, or None on failure.
    """
    if not name or not email:
        print("Error: Name and email cannot be empty.", flush=True)
        return None
    try:
        doc = {"name": name, "email": email}
        result = collection.insert_one(doc)
        return str(result.inserted_id)
    except PyMongoError as e:
        print(f"Error creating user: {e}", flush=True)
        return None

def read_user_by_name(collection: Collection, name: str) -> Optional[Dict[str, Any]]:
    """
    Reads a document from the collection by name.
    :param collection: The MongoDB collection.
    :param name: The name of the user to find.
    :return: The found document, or None if not found or an error occurs.
    """
    if not name:
        print("Error: Name cannot be empty.", flush=True)
        return None
    try:
        return collection.find_one({"name": name})
    except PyMongoError as e:
        print(f"Error reading user: {e}", flush=True)
        return None

def update_user_email(collection: Collection, name: str, new_email: str) -> bool:
    """
    Updates a user's email by their name.
    :param collection: The MongoDB collection.
    :param name: The name of the user to update.
    :param new_email: The new email address.
    :return: True if the update was successful, False otherwise.
    """
    if not name or not new_email:
        print("Error: Name and new email cannot be empty.", flush=True)
        return False
    try:
        result = collection.update_one({"name": name}, {"$set": {"email": new_email}})
        return result.modified_count > 0
    except PyMongoError as e:
        print(f"Error updating user: {e}", flush=True)
        return False

def delete_user(collection: Collection, name: str) -> bool:
    """
    Deletes a user by their name.
    :param collection: The MongoDB collection.
    :param name: The name of the user to delete.
    :return: True if the deletion was successful, False otherwise.
    """
    if not name:
        print("Error: Name cannot be empty.", flush=True)
        return False
    try:
        result = collection.delete_one({"name": name})
        return result.deleted_count > 0
    except PyMongoError as e:
        print(f"Error deleting user: {e}", flush=True)
        return False

def main():
    """Main function to run CRUD operations test cases."""
    client: Optional[MongoClient] = None
    try:
        client = MongoClient(URI)
        db = client[DATABASE_NAME]
        collection = db[COLLECTION_NAME]

        # Clean up the collection before running tests
        collection.drop()
        print("Collection dropped for a clean test run.", flush=True)

        print("--- MongoDB CRUD Operations in Python ---", flush=True)

        # 1. Create Operation
        print("\n[Test Case 1: Create]", flush=True)
        new_user_id = create_user(collection, "Jane Doe", "jane.doe@example.com")
        if new_user_id:
            print(f"User created successfully with ID: {new_user_id}", flush=True)
        else:
            print("User creation failed.", flush=True)

        # 2. Read Operation
        print("\n[Test Case 2: Read]", flush=True)
        user = read_user_by_name(collection, "Jane Doe")
        if user:
            print(f"User found: {user}", flush=True)
        else:
            print("User 'Jane Doe' not found.", flush=True)

        # 3. Update Operation
        print("\n[Test Case 3: Update]", flush=True)
        updated = update_user_email(collection, "Jane Doe", "j.doe.new@example.com")
        if updated:
            print("User 'Jane Doe' updated successfully.", flush=True)
        else:
            print("User update failed.", flush=True)

        # 4. Read again to verify update
        print("\n[Test Case 4: Verify Update]", flush=True)
        user = read_user_by_name(collection, "Jane Doe")
        if user:
            print(f"User found after update: {user}", flush=True)
        else:
            print("User 'Jane Doe' not found after update.", flush=True)

        # 5. Delete Operation
        print("\n[Test Case 5: Delete]", flush=True)
        deleted = delete_user(collection, "Jane Doe")
        if deleted:
            print("User 'Jane Doe' deleted successfully.", flush=True)
        else:
            print("User deletion failed.", flush=True)
        
        # Verify deletion
        user = read_user_by_name(collection, "Jane Doe")
        if user is None:
            print("Successfully verified that 'Jane Doe' is no longer in the database.", flush=True)
        else:
            print("Verification failed: 'Jane Doe' still exists.", flush=True)

    except PyMongoError as e:
        print(f"An error occurred with MongoDB connection: {e}", flush=True)
    finally:
        if client:
            client.close()

if __name__ == "__main__":
    main()