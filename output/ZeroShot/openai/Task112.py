import os
from typing import Any, Dict, List, Optional
from bson import ObjectId
from pymongo import MongoClient
from pymongo.collection import Collection

class Task112:
    @staticmethod
    def _create_client() -> MongoClient:
        uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
        # Use directConnection false to allow SRV discovery if provided; keep defaults secure
        return MongoClient(uri, serverSelectionTimeoutMS=10000, connectTimeoutMS=10000, socketTimeoutMS=15000, maxPoolSize=20)

    @staticmethod
    def _get_collection(client: MongoClient, db_name: str, coll_name: str) -> Collection:
        assert client is not None and db_name and coll_name
        return client[db_name][coll_name]

    @staticmethod
    def _validate_keys(d: Dict[str, Any]) -> None:
        for k, v in d.items():
            if not k or k.startswith('$') or '.' in k:
                raise ValueError(f"Invalid field name: {k}")
            if isinstance(v, dict):
                Task112._validate_keys(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        Task112._validate_keys(item)

    @staticmethod
    def create_one(client: MongoClient, db_name: str, coll_name: str, data: Dict[str, Any]) -> str:
        Task112._validate_keys(data)
        col = Task112._get_collection(client, db_name, coll_name)
        res = col.insert_one(data)
        return str(res.inserted_id)

    @staticmethod
    def read_one_by_id(client: MongoClient, db_name: str, coll_name: str, _id: str) -> Optional[Dict[str, Any]]:
        col = Task112._get_collection(client, db_name, coll_name)
        try:
            oid = ObjectId(_id)
        except Exception as e:
            raise ValueError(f"Invalid ObjectId: {_id}") from e
        doc = col.find_one({"_id": oid})
        return doc

    @staticmethod
    def update_one_by_id(client: MongoClient, db_name: str, coll_name: str, _id: str, updates: Dict[str, Any]) -> int:
        Task112._validate_keys(updates)
        col = Task112._get_collection(client, db_name, coll_name)
        try:
            oid = ObjectId(_id)
        except Exception as e:
            raise ValueError(f"Invalid ObjectId: {_id}") from e
        res = col.update_one({"_id": oid}, {"$set": updates})
        return res.modified_count

    @staticmethod
    def delete_one_by_id(client: MongoClient, db_name: str, coll_name: str, _id: str) -> int:
        col = Task112._get_collection(client, db_name, coll_name)
        try:
            oid = ObjectId(_id)
        except Exception as e:
            raise ValueError(f"Invalid ObjectId: {_id}") from e
        res = col.delete_one({"_id": oid})
        return res.deleted_count

    @staticmethod
    def list_all(client: MongoClient, db_name: str, coll_name: str, limit: int = 10) -> List[Dict[str, Any]]:
        col = Task112._get_collection(client, db_name, coll_name)
        cursor = col.find().limit(max(0, limit))
        return list(cursor)

if __name__ == "__main__":
    try:
        client = Task112._create_client()
        db = "task112_db_py"
        coll = "items"

        # Clean collection
        try:
            client[db][coll].drop()
        except Exception:
            pass

        # Test 1: Create
        data = {"name": "Gadget", "qty": 5, "meta": {"color": "red", "fragile": False}}
        new_id = Task112.create_one(client, db, coll, data)
        print(f"Created ID: {new_id}")

        # Test 2: Read
        doc = Task112.read_one_by_id(client, db, coll, new_id)
        print(f"Read: {doc}")

        # Test 3: Update
        modified = Task112.update_one_by_id(client, db, coll, new_id, {"qty": 100, "tags": ["featured", "popular"]})
        print(f"Modified count: {modified}")

        # Test 4: List
        docs = Task112.list_all(client, db, coll, 10)
        print(f"List count: {len(docs)}")
        for d in docs:
            print(d)

        # Test 5: Delete and verify
        deleted = Task112.delete_one_by_id(client, db, coll, new_id)
        print(f"Deleted count: {deleted}")
        doc2 = Task112.read_one_by_id(client, db, coll, new_id)
        print(f"Post-delete read (should be None): {doc2}")
    except Exception as e:
        print(f"An error occurred. Details: {type(e).__name__}: {e}")