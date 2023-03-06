#!/usr/bin/env python3
"""Base 64 encryption"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ A func that Use the bcrypt package to perform the hashing"""
    codedPass = password.encode()
    return bcrypt.hashpw(codedPass, bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ A function that Uses bcrypt to validate that the provided
        password matches the hashed password.
    """
    valid = False
    pass_encoded = password.encode()
    if bcrypt.checkpw(pass_encoded, hashed_password):
        valid = True
    return valid
