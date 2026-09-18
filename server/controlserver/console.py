from pathlib import Path
from flask import Blueprint, Response, redirect

console_bp = Blueprint("console", __name__)
HTML_PATH = Path(__file__).parent / "templates" / "console.html"


@console_bp.get("/")
def index():
    return redirect("/console", code=302)


@console_bp.get("/console")
def console():
    response = Response(HTML_PATH.read_text(encoding="utf-8"), content_type="text/html; charset=utf-8")
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
