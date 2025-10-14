# You must install pymongo: pip install pymongo
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure

class MongoCRUD:
    def __init__(self, connection_string, db_name, collection_name):
        """
        Initializes the MongoDB connection.
        """
        self.client = None
        self.db = None
        self.collection = None
        try:
            self.client = MongoClient(connection_string)
            # The ismaster command is cheap and does not require auth.
            self.client.admin.command('ismaster')
            self.db = self.client[db_name]
            self.collection = self.db[collection_name]
        except ConnectionFailure as e:
            print(f"Could not connect to MongoDB: {e}")
            raise

    def create_user(self, user_doc):
        """
        Creates (inserts) a new document.
        :param user_doc: A dictionary representing the user document.
        :return: The ObjectId of the inserted document, or None on failure.
        """
        try:
            result = self.collection.insert_one(user_doc)
            return result.inserted_id
        except OperationFailure as e:
            print(f"Error creating user: {e}")
            return None

    def read_user(self, query):
        """
        Reads a document based on a query.
        :param query: A dictionary representing the query.
        :return: The found document as a dictionary, or None if not found.
        """
        try:
            return self.collection.find_one(query)
        except OperationFailure as e:
            print(f"Error reading user: {e}")
            return None

    def update_user(self, query, new_values):
        """
        Updates a single document.
        :param query: A dictionary representing the query to find the document.
        :param new_values: A dictionary for the $set operation.
        :return: The number of documents modified.
        """
        try:
            update_op = {"$set": new_values}
            result = self.collection.update_one(query, update_op)
            return result.modified_count
        except OperationFailure as e:
            print(f"Error updating user: {e}")
            return 0

    def delete_user(self, query):
        """
        Deletes a single document.
        :param query: A dictionary representing the query to find the document.
        :return: The number of documents deleted.
        """
        try:
            result = self.collection.delete_one(query)
            return result.deleted_count
        except OperationFailure as e:
            print(f"Error deleting user: {e}")
            return 0
    
    def close(self):
        """
        Closes the MongoDB client connection.
        """
        if self.client:
            self.client.close()

def main():
    """ Main function to run test cases """
    CONNECTION_STRING = "mongodb://localhost:27017/"
    DB_NAME = "python_test_db"
    COLLECTION_NAME = "users"

    try:
        crud = MongoCRUD(CONNECTION_STRING, DB_NAME, COLLECTION_NAME)
    except ConnectionFailure:
        return

    # Clean up collection before tests
    crud.collection.drop()
    print("--- Starting MongoDB CRUD Test Cases ---")

    try:
        # Test Case 1: Create
        print("\n--- Test Case 1: Create User ---")
        new_user = {"name": "Jane Doe", "age": 28, "city": "London"}
        user_id = crud.create_user(new_user)
        if user_id:
            print(f"User created successfully with ID: {user_id}")
        else:
            print("User creation failed.")
        
        query = {"_id": user_id}

        # Test Case 2: Read
        print("\n--- Test Case 2: Read User ---")
        found_user = crud.read_user(query)
        if found_user:
            print(f"User found: {found_user}")
        else:
            print("User not found.")

        # Test Case 3: Update
        print("\n--- Test Case 3: Update User ---")
        update_data = {"age": 29, "city": "Paris"}
        modified_count = crud.update_user(query, update_data)
        print(f"Users updated: {modified_count}")

        # Test Case 4: Read after Update
        print("\n--- Test Case 4: Read User After Update ---")
        updated_user = crud.read_user(query)
        if updated_user:
            print(f"User found after update: {updated_user}")
        else:
            print("User not found.")

        # Test Case 5: Delete
        print("\n--- Test Case 5: Delete User ---")
        deleted_count = crud.delete_user(query)
        print(f"Users deleted: {deleted_count}")
        deleted_user = crud.read_user(query)
        if deleted_user is None:
            print("User successfully deleted and not found.")
        else:
            print("User deletion failed.")

    finally:
        crud.close()
        print("\n--- Tests Finished ---")


if __name__ == "__main__":
    main()