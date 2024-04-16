#!/usr/bin/env python3
"""Aunthetication module"""
from typing import List, TypeVar
from flask import request


class Auth:
    """Authorization class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Aunthetication requirement"""
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != "/":
            path += "/"

        return path not in excluded_paths

    def authorization_header(self, request=None) -> str:
        """Authorization header"""
        if request is None:
            return None
        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar("User"):
        """Current user request"""
        return None
