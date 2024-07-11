#!/usr/bin/env python3
"""
    File encrypt password
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ return bytes """
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ return is valid bool """
    valid = False
    encoded = password.encode()
    if bcrypt.checkpw(encoded, hashed_password):
        valid = True
    return valid
