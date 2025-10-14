from typing import Any, Dict, List, Optional
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from bson import ObjectId
from bson.json_util import dumps
import re

MAX_URI_LEN = 2048
MAX_NAME_LEN = 64
MAX_STRING_LEN = 256
MAX_KEYS = 50
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def validate_uri(uri: str) -> bool:
    if not isinstance(uri, str):
        return False
    if len(uri) == 0 or len(uri) > MAX_URI_LEN:
        return False
    trimmed = uri.strip()
    return trimmed.startswith("mongodb://") or trimmed.startswith("mongodb+srv://")


def validate_name(name: str) -> bool:
    if not isinstance(name, str):
        return False
    if len(name) == 0 or len(name) > MAX_NAME_LEN:
        return False
    return NAME_RE.match(name) is not None


def sanitize_value(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, str):
        s = v[:MAX_STRING_LEN]
        return s.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")
    if isinstance(v, (int, float, bool)):
        return v
    if isinstance(v, dict):
        return map_to_safe_document(v)
    if isinstance(v, list):
        safe_list: List[Any] = []
        for i, item in enumerate(v):
            if i >= MAX_KEYS:
                break
            safe_list.append(sanitize_value(item))
        return safe_list
    s = str(v)[:MAX_STRING_LEN]
    return s


def map_to_safe_document(data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("data must be a dict")
    if len(data) > MAX_KEYS:
        raise ValueError("too many keys")
    out: Dict[str, Any] = {}
    for k, v in data.items():
        if not isinstance(k, str) or len(k) == 0 or len(k) > MAX_NAME_LEN or not NAME_RE.match(k):
            raise ValueError("invalid key")
        out[k] = sanitize_value(v)
    return out


def create_one(uri: str, db_name: str, coll_name: str, data: Dict[str, Any]) -> str:
    if not validate_uri(uri):
        raise ValueError("Invalid MongoDB URI")
    if not validate_name(db_name) or not validate_name(coll_name):
        raise ValueError("Invalid database/collection name")
    safe_doc = map_to_safe_document(data)
    with MongoClient(
        uri,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        socketTimeoutMS=10000,
        appname="Task112App",
        uuidRepresentation="standard",
    ) as client:
        coll = client[db_name][coll_name]
        result = coll.insert_one(safe_doc)
        return str(result.inserted_id)


def read_one_by_id(uri: str, db_name: str, coll_name: str, id_hex: str) -> Optional[str]:
    if not validate_uri(uri):
        raise ValueError("Invalid MongoDB URI")
    if not validate_name(db_name) or not validate_name(coll_name):
        raise ValueError("Invalid database/collection name")
    try:
        oid = ObjectId(id_hex)
    except Exception as e:
        raise ValueError("Invalid ObjectId format") from e
    with MongoClient(
        uri,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        socketTimeoutMS=10000,
        appname="Task112App",
        uuidRepresentation="standard",
    ) as client:
        coll = client[db_name][coll_name]
        doc = coll.find_one({"_id": oid})
        if doc is None:
            return None
        return dumps(doc)  # relaxed extended JSON


def read_many(uri: str, db_name: str, coll_name: str, limit: int) -> List[str]:
    if not validate_uri(uri):
        raise ValueError("Invalid MongoDB URI")
    if not validate_name(db_name) or not validate_name(coll_name):
        raise ValueError("Invalid database/collection name")
    lim = max(0, min(limit, 100))
    out: List[str] = []
    with MongoClient(
        uri,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        socketTimeoutMS=10000,
        appname="Task112App",
        uuidRepresentation="standard",
    ) as client:
        coll = client[db_name][coll_name]
        for doc in coll.find().limit(lim):
            out.append(dumps(doc))
    return out


def update_one_by_id(uri: str, db_name: str, coll_name: str, id_hex: str, updates: Dict[str, Any]) -> bool:
    if not validate_uri(uri):
        raise ValueError("Invalid MongoDB URI")
    if not validate_name(db_name) or not validate_name(coll_name):
        raise ValueError("Invalid database/collection name")
    try:
        oid = ObjectId(id_hex)
    except Exception as e:
        raise ValueError("Invalid ObjectId format") from e
    safe_updates = map_to_safe_document(updates)
    with MongoClient(
        uri,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        socketTimeoutMS=10000,
        appname="Task112App",
        uuidRepresentation="standard",
    ) as client:
        coll = client[db_name][coll_name]
        res = coll.update_one({"_id": oid}, {"$set": safe_updates})
        return res.matched_count > 0


def delete_one_by_id(uri: str, db_name: str, coll_name: str, id_hex: str) -> bool:
    if not validate_uri(uri):
        raise ValueError("Invalid MongoDB URI")
    if not validate_name(db_name) or not validate_name(coll_name):
        raise ValueError("Invalid database/collection name")
    try:
        oid = ObjectId(id_hex)
    except Exception as e:
        raise ValueError("Invalid ObjectId format") from e
    with MongoClient(
        uri,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        socketTimeoutMS=10000,
        appname="Task112App",
        uuidRepresentation="standard",
    ) as client:
        coll = client[db_name][coll_name]
        res = coll.delete_one({"_id": oid})
        return res.deleted_count > 0


def _run_tests() -> None:
    uri = "mongodb://127.0.0.1:27017"
    db = "testdb_secure_py"
    coll = "items_secure_py"
    try:
        # 1) Create
        new_id = create_one(uri, db, coll, {"name": "alpha", "count": 1, "active": True})
        print("Create insertedId:", new_id)

        # 2) Read by ID
        doc_json = read_one_by_id(uri, db, coll, new_id)
        print("Read by ID:", doc_json)

        # 3) Update by ID
        updated = update_one_by_id(uri, db, coll, new_id, {"count": 2, "desc": "updated"})
        print("Update result:", updated)

        # 4) Read many
        many = read_many(uri, db, coll, 5)
        print("Read many (", len(many), "):", many)

        # 5) Delete by ID
        deleted = delete_one_by_id(uri, db, coll, new_id)
        print("Delete result:", deleted)

        # Extra: Read non-existing
        missing = read_one_by_id(uri, db, coll, "000000000000000000000000")
        print("Read missing (should be None):", missing)

    except (ValueError, PyMongoError) as ex:
        print("Operation failed securely:", str(ex))


if __name__ == "__main__":
    _run_tests()