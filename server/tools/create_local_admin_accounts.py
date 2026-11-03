"""Create a new private local-account file. Never prints passwords or hashes."""
import argparse
import getpass
import json
import os
import re
from werkzeug.security import generate_password_hash


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True, help="New private account JSON file")
    parser.add_argument("--account", action="append", required=True, help="username:admin|operator|viewer; repeat for multiple accounts")
    args = parser.parse_args()
    accounts, names = [], set()
    for spec in args.account:
        name, sep, role = spec.partition(":")
        if not sep or not re.fullmatch(r"[A-Za-z0-9._@-]{1,64}", name) or name in names or role not in ("admin", "operator", "viewer"):
            parser.error("Invalid or duplicate account specification")
        names.add(name)
        password = getpass.getpass(f"Password for {name}: ")
        if len(password) < 12 or len(password) > 512 or password != getpass.getpass(f"Repeat password for {name}: "):
            parser.error("Passwords must match and contain 12 to 512 characters")
        accounts.append({"username": name, "role": role, "passwordHash": generate_password_hash(password)})
    if not any(a["role"] == "admin" for a in accounts):
        parser.error("At least one administrator is required")
    fd = os.open(args.file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(accounts, out, ensure_ascii=False, indent=2)
        out.write("\n")
    print("Created local account file. Protect it and its containing directory.")


if __name__ == "__main__":
    main()
