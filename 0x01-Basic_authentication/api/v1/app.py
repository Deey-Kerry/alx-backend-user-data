#!/usr/bin/env python3
"""
Basic Authorization for API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request, abort
from flask_cors import CORS, cross_origin
import os
from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth

app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})


auth = None
if os.getenv("AUTH_TYPE") == "basic_auth":
    auth = BasicAuth()
elif os.getenv("AUTH_TYPE") == "auth":
    auth = Auth()


@app.before_request
def before_request_func():
    """Function that makes requests"""
    if auth is None:
        return
    if not auth.require_auth(request.path, ['/api/v1/status/',
                                            '/api/v1/unauthorized/',
                                            '/api/v1/forbidden/']):
        return
    if auth.authorization_header(request) is None:
        abort(401)
    if auth.current_user(request) is None:
        abort(403)


@app.errorhandler(401)
def unauthorized(error) -> str:
    """Unauthorized error handler"""
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error):
    """Forbidden Error handling 403"""
    return jsonify({"error": "Forbidden"}), 403


@app.errorhandler(404)
def not_found(error) -> str:
    """Not found Error"""
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
