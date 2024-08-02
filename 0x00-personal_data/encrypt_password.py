#!/usr/bin/env python3
"""
encrypting passwords module
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using a random salt.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    The Checks is the given password was formed to a hashed password.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
