#!/usr/bin/env python3
"""Implement a hash_password function that expects one
string argument name password and returns a salted,
hashed password
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """It hashes the password instead of plain text
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Checks if the password is valid or not
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
