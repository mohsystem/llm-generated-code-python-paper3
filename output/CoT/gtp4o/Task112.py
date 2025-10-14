import os
from typing import Any, Dict, List, Optional
from pymongo import MongoClient, ReadConcern, WriteConcern
from pymongo.collection import Collection
from pymongo.errors import PyMongoError


def create_client(uri: Optional[str] = None) -> MongoClient:
    if not uri:
        uri = os.getenv("MONGODB_URI")
    if not uri:
        uri = "mongodb://localhost:27017/?retryWrites=true&w=majority"
    # Configure timeouts securely
    client = MongoClient(
        uri,
        serverSelectionTimeoutMS=10000,
        connectTimeoutMS=10000,
        socketTimeoutMS=15000,
        tlsAllowInvalidCertificates=False,
        retryWrites=True,
        appname="Task112PythonClient",
    )
    return client


def get_collection(client: MongoClient, db_name: str, coll_name: str) -> Collection:
    db = client[db_name]
    # Apply safe concerns
    return db.get_collection(coll_name, read_concern=ReadConcern("majority"), write_concern=WriteConcern("majority"))


def create_document(collection: Collection, document: Dict[str, Any]) -> Any:
    if collection is None or document is None:
        raise ValueError("collection/document cannot be None")
    res = collection.insert_one(document)
    return res.inserted_id


def read_documents(collection: Collection, filter_doc: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    if collection is None:
        raise ValueError("collection cannot be None")
    if filter_doc is None:
        filter_doc = {}
    return list(collection.find(filter_doc))


def update_documents(collection: Collection, filter_doc: Dict[str, Any], update_doc: Dict[str, Any]) -> int:
    if collection is None or filter_doc is None or update_doc is None:
        raise ValueError("arguments cannot be None")
    res = collection.update_many(filter_doc, update_doc)
    return int(res.modified_count)


def delete_documents(collection: Collection, filter_doc: Dict[str, Any]) -> int:
    if collection is None or filter_doc is None:
        raise ValueError("arguments cannot be None")
    res = collection.delete_many(filter_doc)
    return int(res.deleted_count)


def main():
    db_name = "task112db"
    coll_name = "users"
    tag_value = "task112"
    client = None
    try:
        client = create_client()
        coll = get_collection(client, db_name, coll_name)

        # Test 1: Cleanup
        cleaned = delete_documents(coll, {"tag": tag_value})
        print(f"Test1-Cleanup deleted: {cleaned}")

        # Test 2: Create
        alice = {"username": "alice", "email": "alice.task112@example.com", "age": 30, "tag": tag_value}
        inserted_id = create_document(coll, alice)
        print(f"Test2-Create insertedId: {inserted_id}")

        # Test 3: Read
        found = read_documents(coll, {"username": "alice", "tag": tag_value})
        print(f"Test3-Read count: {len(found)}")

        # Test 4: Update
        modified = update_documents(coll, {"username": "alice", "tag": tag_value}, {"$set": {"age": 31}})
        print(f"Test4-Update modified: {modified}")

        # Test 5: Delete
        deleted = delete_documents(coll, {"username": "alice", "tag": tag_value})
        print(f"Test5-Delete deleted: {deleted}")

    except PyMongoError as e:
        print(f"MongoDB error: {e}")
    finally:
        if client:
            client.close()


if __name__ == "__main__":
    main()