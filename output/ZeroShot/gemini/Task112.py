import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
from bson.objectid import ObjectId

# Note: To run this code, you need the pymongo library.
# Install it using pip:
# pip install pymongo

# IMPORTANT: In a production environment, connection strings should never be hard-coded.
# They should be retrieved from a secure source like environment variables or a secrets manager.
# The user in the connection string should have the minimum required permissions.
CONNECTION_STRING = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DATABASE_NAME = "mySecureDb"
COLLECTION_NAME = "users"

def create_document(collection, user_document):
    """
    Creates a new document in the collection.
    :param collection: The pymongo collection object.
    :param user_document: A dictionary representing the document.
    :return: The ObjectId of the newly created document or None on failure.
    """
    try:
        # Input validation should be performed here in a real application
        # to prevent NoSQL injection if data comes from external sources.
        result = collection.insert_one(user_document)
        print(f"Create: Success. Inserted document with id: {result.inserted_id}")
        return result.inserted_id
    except OperationFailure as e:
        print(f"An error occurred during create operation: {e.details}")
        return None

def read_document(collection, doc_id):
    """
    Reads a document from the collection by its ID.
    :param collection: The pymongo collection object.
    :param doc_id: The ObjectId of the document to find.
    :return: The found document or None.
    """
    try:
        document = collection.find_one({"_id": doc_id})
        if document:
            print(f"Read: Success. Found document: {document}")
        else:
            print(f"Read: Document with id {doc_id} not found.")
        return document
    except OperationFailure as e:
        print(f"An error occurred during read operation: {e.details}")
        return None

def update_document(collection, doc_id, update_data):
    """
    Updates a document in the collection.
    :param collection: The pymongo collection object.
    :param doc_id: The ObjectId of the document to update.
    :param update_data: A dictionary with the fields to update.
    :return: True if the update was successful, False otherwise.
    """
    try:
        result = collection.update_one({"_id": doc_id}, {"$set": update_data})
        print(f"Update: Success. Matched {result.matched_count} and modified {result.modified_count} document(s).")
        return result.modified_count > 0
    except OperationFailure as e:
        print(f"An error occurred during update operation: {e.details}")
        return False

def delete_document(collection, doc_id):
    """
    Deletes a document from the collection by its ID.
    :param collection: The pymongo collection object.
    :param doc_id: The ObjectId of the document to delete.
    :return: True if the deletion was successful, False otherwise.
    """
    try:
        result = collection.delete_one({"_id": doc_id})
        print(f"Delete: Success. Deleted {result.deleted_count} document(s).")
        return result.deleted_count > 0
    except OperationFailure as e:
        print(f"An error occurred during delete operation: {e.details}")
        return False

def main():
    """Main function to run the test cases."""
    client = None
    try:
        client = MongoClient(CONNECTION_STRING)
        # The ismaster command is cheap and does not require auth.
        client.admin.command('ismaster')
        print("Successfully connected to MongoDB.")
        
        db = client[DATABASE_NAME]
        collection = db[COLLECTION_NAME]

        # Cleanup before tests
        collection.drop()
        print("--- Starting Test Cases ---")

        # --- Test Case 1: Create a new user ---
        print("\n1. === CREATE Operation ===")
        new_user = {"name": "Jane Doe", "age": 28, "email": "jane.doe@example.com"}
        user_id = create_document(collection, new_user)

        if user_id:
            # --- Test Case 2: Read the created user ---
            print("\n2. === READ Operation (after create) ===")
            read_document(collection, user_id)

            # --- Test Case 3: Update the user's email ---
            print("\n3. === UPDATE Operation ===")
            update_document(collection, user_id, {"email": "jane.d@example.com", "status": "active"})

            # --- Test Case 4: Read the updated user ---
            print("\n4. === READ Operation (after update) ===")
            read_document(collection, user_id)

            # --- Test Case 5: Delete the user ---
            print("\n5. === DELETE Operation ===")
            delete_document(collection, user_id)

            # --- Final check: try to read the deleted user ---
            print("\n--- Final Check: Verifying Deletion ---")
            read_document(collection, user_id)
        else:
            print("Test cases aborted due to creation failure.")
        
        print("\n--- Test Cases Finished ---")

    except ConnectionFailure as e:
        print(f"Failed to connect to MongoDB: {e}")
    finally:
        if client:
            client.close()
            print("\nMongoDB connection closed.")

if __name__ == "__main__":
    main()