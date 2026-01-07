import hmac
import hashlib
import secrets
from flask import session
from werkzeug.security import generate_password_hash
from config import PASSWORD_HASH_FILE, ACCESS_TOKEN_FILE, FIRST_START_FILE


def is_logged_in():
    return session.get("logged_in")


def _get_secret_key(secret_key):
    # Accept the secret key as an argument
    return secret_key.encode() if isinstance(secret_key, str) else secret_key


def hash_token(token, secret_key):
    return hmac.new(
        _get_secret_key(secret_key), token.encode(), hashlib.sha256
    ).hexdigest()


def store_token_hash(token, secret_key):
    token_hash = hash_token(token, secret_key)
    with open(ACCESS_TOKEN_FILE, "w") as f:
        f.write(token_hash)
    return token_hash


def verify_token(token, secret_key):
    if not ACCESS_TOKEN_FILE.exists():
        return False
    token_hash = hash_token(token, secret_key)
    with open(ACCESS_TOKEN_FILE) as f:
        stored_hash = f.read().strip()
    return hmac.compare_digest(token_hash, stored_hash)


def ensure_initial_password_and_token(secret_key):
    if not PASSWORD_HASH_FILE.exists():
        password = secrets.token_urlsafe(6)[:8]
        pw_hash = generate_password_hash(password)
        with open(PASSWORD_HASH_FILE, "w") as f:
            f.write(pw_hash)
        with open(FIRST_START_FILE, "w") as f:
            f.write(password)
        print("\n*** nanoCMS FIRST START ***")
        print(f"Temporary admin password: {password}")
        print("You will be required to set a new password on first login.\n")
    if not ACCESS_TOKEN_FILE.exists():
        token = secrets.token_urlsafe(24)
        store_token_hash(token, secret_key)
        print(f"API access token generated: {token}\n")


def get_access_token():
    if ACCESS_TOKEN_FILE.exists():
        with open(ACCESS_TOKEN_FILE) as f:
            return f.read().strip()
    return None
