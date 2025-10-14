import pymongo
from pymongo import MongoClient
from bson.objectid import ObjectId

# NOTE: To run this code, you need the pymongo library.
# Install it using pip:
# pip install pymongo

# --- CRUD Functions ---

def create_document(collection, document):
    """Inserts a single document into the collection."""
    try:
        result = collection.insert_one(document)
        print(f"Success: Document inserted with id: {result.inserted_id}")
        return result.inserted_id
    except Exception as e:
        print(f"Error inserting document: {e}")
        return None

def read_document(collection, query):
    """Finds and returns a single document matching the query."""
    try:
        document = collection.find_one(query)
        return document
    except Exception as e:
        print(f"Error reading document: {e}")
        return None

def update_document(collection, filter_query, update_data):
    """Updates a single document matching the filter."""
    try:
        result = collection.update_one(filter_query, {"$set": update_data})
        print(f"Success: Matched {result.matched_count} and modified {result.modified_count} document(s).")
        return result.modified_count > 0
    except Exception as e:
        print(f"Error updating document: {e}")
        return False

def delete_document(collection, query):
    """Deletes a single document matching the query."""
    try:
        result = collection.delete_one(query)
        print(f"Success: Deleted {result.deleted_count} document(s).")
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting document: {e}")
        return False

# --- Main execution block with test cases ---
def main():
    # --- Connection Setup ---
    # Ensure you have MongoDB running on localhost:27017
    client = None
    try:
        uri = "mongodb://localhost:27017/"
        db_name = "pythonTestDB"
        collection_name = "users"
        
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        # The ismaster command is cheap and does not require auth.
        client.admin.command('ismaster')
        print("MongoDB connection successful.")

        db = client[db_name]
        collection = db[collection_name]

        # Clean up previous runs
        collection.drop()
        print(f"--- Starting CRUD Test Cases on '{db_name}.{collection_name}' ---")

        # --- Test Case 1: Create ---
        print("\n1. CREATE Operation")
        doc_to_create = {"name": "Alan Turing", "age": 41, "profession": "Computer Scientist"}
        create_document(collection, doc_to_create)

        # --- Test Case 2: Read ---
        print("\n2. READ Operation")
        query_read = {"name": "Alan Turing"}
        found_doc = read_document(collection, query_read)
        print(f"Found document: {found_doc}")

        # --- Test Case 3: Update ---
        print("\n3. UPDATE Operation")
        query_update = {"name": "Alan Turing"}
        data_to_update = {"age": 42}
        update_document(collection, query_update, data_to_update)

        # --- Test Case 4: Read after Update ---
        print("\n4. READ Operation (after update)")
        updated_doc = read_document(collection, query_read)
        print(f"Found updated document: {updated_doc}")
        
        # --- Test Case 5: Delete ---
        print("\n5. DELETE Operation")
        query_delete = {"name": "Alan Turing"}
        delete_document(collection, query_delete)
        deleted_doc = read_document(collection, query_delete)
        print(f"Document after deletion attempt: {deleted_doc}")

        print("\n--- CRUD Test Cases Finished ---")

        # --- Final Cleanup ---
        print("Dropping collection...")
        collection.drop()
        print("Collection dropped.")

    except pymongo.errors.ConnectionFailure as e:
        print(f"Could not connect to MongoDB: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if client:
            client.close()
            print("MongoDB connection closed.")

if __name__ == "__main__":
    main()