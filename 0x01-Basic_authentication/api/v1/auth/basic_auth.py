#!/usr/bin/env python3
""" Module Basic_auth for user authentication
"""
from typing import TypeVar, Tuple
from base64 import b64decode, decode
from api.v1.auth.auth import Auth
from models.user import User
import base64
import binascii


class BasicAuth(Auth):
    """ Extends BasicAuth class """
    def extract_base64_authorization_header(self, auth_header: str) -> str:
        """ Extract base64 authorization header """
        if auth_header is None or not isinstance(auth_header, str):
            return None
        return None if 'Basic ' not in auth_header else auth_header[6:]

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str,
            ) -> str:
        """Decodes a base64-encoded authorization header.
        """
        if type(base64_authorization_header) == str:
            try:
                res = base64.b64decode(
                    base64_authorization_header,
                    validate=True,
                )
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

  
    def extract_user_credentials(
            self, decoded_b64_auth_header: str) -> Tuple[str, str]:
        """ Returns credentials """
        if decoded_b64_auth_header is None or not isinstance(
                decoded_b64_auth_header, str) \
           or ':' not in decoded_b64_auth_header:
            return (None, None)
        return decoded_b64_auth_header.split(':', 1)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """ Returns user object from credentials """
        if user_email is None or not isinstance(
                user_email, str) or user_pwd is None or not isinstance(
                    user_pwd, str):
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None
        for user in users:
            return user if user.is_valid_password(user_pwd) else None


def current_user(self, request=None) -> TypeVar('User'):
    """overloads Auth and retrieves the User instance for a request"""
    auth_header = self.authorization_header(request)
    if not auth_header:
        return None
    extract = self.extract_base64_authorization_header(auth_header)
    decode = self.decode_base64_authorization_header(extract)
    credentials = self.extract_user_credentials(decode)
    user_email = credentials[0]
    user_password = credentials[1]
    credentials = self.user_object_from_credentials(
        user_email, user_password)
    return credentials
