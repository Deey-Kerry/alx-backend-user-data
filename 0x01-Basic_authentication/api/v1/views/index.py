#!/usr/bin/env python3
""" Function for Index views
"""
from flask import jsonify, abort
from api.v1.views import app_views


@app_views.route("/status", methods=["GET"], strict_slashes=False)
def status() -> str:
    """GET status
    """
    return jsonify({"status": "OK"})


@app_views.route("/stats/", strict_slashes=False)
def stats() -> str:
    """GET stats
    """
    from models.user import User

    stats = {}
    stats["users"] = User.count()
    return jsonify(stats)


@app_views.route("/unauthorized", methods=["GET"], strict_slashes=False)
def unauthorized():
    """Unauthorized views"""
    abort(401)


@app_views.route("/forbidden", methods=["GET"], strict_slashes=False)
def forbidden():
    """Forbidden views"""
    abort(403)
