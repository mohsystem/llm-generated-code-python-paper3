from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple
import re

MAGIC = b"USR1"
VERSION = 1
USERNAME_MIN = 1
USERNAME_MAX = 64
EMAIL_MIN = 3
EMAIL_MAX = 254
AGE_MIN = 0
AGE_MAX = 120

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

@dataclass(frozen=True)
class UserRecord:
    user_id: int
    username: str
    age: int
    email: str

def _ensure(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)

def _is_ascii_printable(data: bytes) -> bool:
    return all(0x20 <= b <= 0x7E for b in data)

def serialize(record: UserRecord) -> bytes:
    _ensure(0 <= record.user_id <= 0xFFFFFFFF, "user_id out of range")
    _ensure(record.username is not None and USERNAME_MIN <= len(record.username) <= USERNAME_MAX, "username length invalid")
    _ensure(USERNAME_RE.fullmatch(record.username) is not None, "username content invalid")
    _ensure(AGE_MIN <= record.age <= AGE_MAX, "age out of range")
    _ensure(record.email is not None, "email missing")
    email_b = record.email.encode("utf-8")
    user_b = record.username.encode("utf-8")
    _ensure(_is_ascii_printable(user_b) and _is_ascii_printable(email_b), "Only ASCII allowed")
    _ensure(EMAIL_MIN <= len(email_b) <= EMAIL_MAX, "email length invalid")
    _ensure(EMAIL_RE.fullmatch(record.email) is not None, "email content invalid")

    out = bytearray()
    out += MAGIC
    out.append(VERSION)
    out += bytes([
        (record.user_id >> 24) & 0xFF,
        (record.user_id >> 16) & 0xFF,
        (record.user_id >> 8) & 0xFF,
        record.user_id & 0xFF,
    ])
    out.append(len(user_b))
    out += user_b
    out.append(record.age & 0xFF)
    out.append(len(email_b))
    out += email_b
    return bytes(out)

def deserialize(data: bytes) -> UserRecord:
    _ensure(isinstance(data, (bytes, bytearray)), "data must be bytes")
    pos = 0
    _ensure(len(data) >= 12, "Data too short")
    _ensure(data[:4] == MAGIC, "Invalid magic")
    pos += 4
    version = data[pos]
    pos += 1
    _ensure(version == VERSION, "Unsupported version")

    _ensure(pos + 4 <= len(data), "Insufficient data for user_id")
    user_id = (data[pos] << 24) | (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3]
    pos += 4

    _ensure(pos < len(data), "Missing username length")
    ulen = data[pos]
    pos += 1
    _ensure(USERNAME_MIN <= ulen <= USERNAME_MAX, "Invalid username length")
    _ensure(pos + ulen <= len(data), "Insufficient data for username")
    ubytes = bytes(data[pos:pos+ulen])
    _ensure(_is_ascii_printable(ubytes), "Username not ASCII")
    username = ubytes.decode("utf-8")
    _ensure(USERNAME_RE.fullmatch(username) is not None, "Invalid username content")
    pos += ulen

    _ensure(pos < len(data), "Missing age")
    age = data[pos]
    pos += 1
    _ensure(AGE_MIN <= age <= AGE_MAX, "Invalid age")

    _ensure(pos < len(data), "Missing email length")
    elen = data[pos]
    pos += 1
    _ensure(EMAIL_MIN <= elen <= EMAIL_MAX, "Invalid email length")
    _ensure(pos + elen <= len(data), "Insufficient data for email")
    ebytes = bytes(data[pos:pos+elen])
    _ensure(_is_ascii_printable(ebytes), "Email not ASCII")
    email = ebytes.decode("utf-8")
    _ensure(EMAIL_RE.fullmatch(email) is not None, "Invalid email content")
    pos += elen

    _ensure(pos == len(data), "Trailing data present")
    return UserRecord(user_id=user_id, username=username, age=age, email=email)

def main() -> None:
    # 1) Valid record
    r1 = UserRecord(123456, "alice_01", 30, "alice@example.com")
    d1 = serialize(r1)
    print("T1:", deserialize(d1))

    # 2) Invalid magic
    bad_magic = bytearray(d1)
    bad_magic[0] = ord('B')
    try:
        deserialize(bytes(bad_magic))
        print("T2: Unexpected success")
    except ValueError as e:
        print("T2:", str(e))

    # 3) Invalid age (200)
    bad_age = bytearray(d1)
    # age position: 4 magic + 1 ver + 4 id + 1 ulen + ulen
    ulen = d1[4 + 1 + 4]
    age_pos = 4 + 1 + 4 + 1 + ulen
    bad_age[age_pos] = 200
    try:
        deserialize(bytes(bad_age))
        print("T3: Unexpected success")
    except ValueError as e:
        print("T3:", str(e))

    # 4) Invalid username content (space)
    try:
        serialize(UserRecord(1, "bad name", 22, "bn@example.org"))
        print("T4: Unexpected success")
    except ValueError as e:
        print("T4:", str(e))

    # 5) Invalid email content (missing '@')
    try:
        serialize(UserRecord(2, "bob-77", 44, "bob#example.com"))
        print("T5: Unexpected success")
    except ValueError as e:
        print("T5:", str(e))

if __name__ == "__main__":
    main()