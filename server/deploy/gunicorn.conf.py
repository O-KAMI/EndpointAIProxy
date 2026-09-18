"""Optional equivalent Gunicorn configuration; the default entry point is python app.py."""
from config import Config

settings = Config()
bind = f"{settings.HTTP_HOST}:{settings.HTTP_PORT}"
workers = 2
worker_class = "gthread"
threads = 4
timeout = 60
graceful_timeout = 30
keepalive = 5
preload_app = False
max_requests = 10000
max_requests_jitter = 1000
accesslog = None  # Application logs route templates and request IDs, never headers/body.
errorlog = "-"
capture_output = True
umask = 0o027
# Scheme handling is performed explicitly by app.LoopbackProxy.
secure_scheme_headers = {}
forwarded_allow_ips = ""
