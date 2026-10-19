"""Bounded exception metadata without messages, values, locals or filesystem paths."""
import re

_TYPES = {"RuntimeError", "ValueError", "TypeError", "OSError", "PermissionError",
          "FileNotFoundError", "TimeoutError", "ConnectionError", "OperationalError",
          "InterfaceError", "IntegrityError", "ProgrammingError", "DatabaseError"}


def safe_exception(exc):
    kind = type(exc).__name__
    if kind not in _TYPES:
        kind = "OTHER"
    number = exc.args[0] if exc.args and type(exc.args[0]) is int else getattr(exc, "errno", 0)
    if type(number) is not int or not 0 <= number <= 65535:
        number = 0
    state = getattr(exc, "sqlstate", "")
    if not isinstance(state, str) or not re.fullmatch(r"[A-Z0-9]{5}", state):
        state = ""
    frames = []
    tb = exc.__traceback__
    while tb is not None and len(frames) < 6:
        module = tb.tb_frame.f_globals.get("__name__", "")
        if (module == "app" or module.startswith("controlserver.")) and re.fullmatch(r"[A-Za-z0-9_.]{1,80}", module):
            frames.append(f"{module}:{tb.tb_lineno}")
        tb = tb.tb_next
    return kind, number, state, ",".join(frames)
