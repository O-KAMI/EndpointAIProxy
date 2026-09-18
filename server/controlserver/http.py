"""HTTP helpers: one wire serializer and explicit device identity binding."""
import functools
from flask import current_app, request, Response
from pydantic import ValidationError
from werkzeug.exceptions import BadRequest, UnsupportedMediaType
from .security import dumps, safe_compare
from .validation import ApiProblem


def cfg():
    return current_app.extensions["control_config"]


def store():
    return current_app.extensions["control_store"]


def response(value=None, status=200):
    return Response(dumps(value) if value is not None else "", status=status,
                    content_type="application/json; charset=utf-8")


def parse(model, code):
    try:
        return model.model_validate(request.get_json())
    except (ValidationError, BadRequest, UnsupportedMediaType, ValueError):
        raise ApiProblem(code, "The request body is invalid.") from None


def bearer():
    parts = request.headers.get("Authorization", "").split()
    return parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else None


def token_required(kind):
    def decorator(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            expected = cfg().ADMIN_TOKEN if kind == "admin" else cfg().CLIENT_TOKEN
            token = bearer()
            if not token or not safe_compare(token, expected):
                return response(status=401)
            return func(*args, **kwargs)
        return wrapped
    return decorator


def require_https():
    if cfg().REQUIRE_HTTPS and not request.is_secure:
        raise ApiProblem("DEVICE_CONTROL_HTTPS_REQUIRED", "Device control requires HTTPS.")


def authenticate_device(device):
    token = bearer()
    if not token or not store().authenticate(device, token):
        raise ApiProblem("UNAUTHORIZED", "Unauthorized", 401)
