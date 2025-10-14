from typing import Optional, Dict, Any
from pymongo import MongoClient
from pymongo.collection import Collection

def create_document(collection: Collection, _id: str, name: str, age: int) -> bool:
    try:
        res = collection.insert_one({"_id": _id, "name": name, "age": age})
        return res.acknowledged
    except Exception:
        return False

def read_document(collection: Collection, _id: str) -> Optional[Dict[str, Any]]:
    try:
        return collection.find_one({"_id": _id})
    except Exception:
        return None

def update_document(collection: Collection, _id: str, new_name: str, new_age: int) -> bool:
    try:
        res = collection.update_one({"_id": _id}, {"$set": {"name": new_name, "age": new_age}})
        return res.modified_count > 0
    except Exception:
        return False

def delete_document(collection: Collection, _id: str) -> bool:
    try:
        res = collection.delete_one({"_id": _id})
        return res.deleted_count > 0
    except Exception:
        return False

if __name__ == "__main__":
    uri = "mongodb://localhost:27017"
    client = MongoClient(uri)
    coll = client["task112db"]["py_people"]
    coll.delete_many({"_id": {"$in": ["u1", "u2", "u3", "u4", "u5"]}})

    # Test case 1: Create
    print("Create u1:", create_document(coll, "u1", "Alice", 30))

    # Test case 2: Read
    print("Read u1:", read_document(coll, "u1"))

    # Test case 3: Update
    print("Update u1:", update_document(coll, "u1", "Alicia", 31))
    print("Read u1 after update:", read_document(coll, "u1"))

    # Test case 4: Create another
    print("Create u2:", create_document(coll, "u2", "Bob", 25))

    # Test case 5: Delete
    print("Delete u2:", delete_document(coll, "u2"))