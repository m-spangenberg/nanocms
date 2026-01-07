import logging
import os
import secrets
from datetime import timedelta
from dotenv import load_dotenv
from flask import Flask, abort, request, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect

from .config import (
    DATA_DIR,
    DEFAULTS,
    UPLOAD_FOLDER,
    get_allowed_cors_origins,
    load_settings,
)
from .auth import ensure_initial_password_and_token
from .routes import main_bp

cors = CORS()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

def create_app():
    # Ensure data and upload directories exist
    DATA_DIR.mkdir(exist_ok=True)
    UPLOAD_FOLDER.mkdir(exist_ok=True, parents=True)

    # Auto-generate or persist a secret key in data/secret_key.txt
    load_dotenv()
    SECRET_KEY_FILE = DATA_DIR / "secret_key.txt"

    if SECRET_KEY_FILE.exists():
        secret_key = SECRET_KEY_FILE.read_text().strip()
    else:
        DATA_DIR.mkdir(exist_ok=True)
        secret_key = secrets.token_urlsafe(32)
        SECRET_KEY_FILE.write_text(secret_key)

    system_settings = load_settings()
    MAX_CONTENT_LENGTH = (
        int(system_settings.get("max_content_length", DEFAULTS["max_content_length"]))
        * 1024
        * 1024
    )
    MAX_JSON_SIZE = (
        int(system_settings.get("max_json_size", DEFAULTS["max_json_size"])) * 1024 * 1024
    )

    ensure_initial_password_and_token(secret_key=secret_key)

    # Configure Flask app
    app = Flask(__name__)
    app.secret_key = secret_key
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    app.config["SESSION_COOKIE_SECURE"] = bool(
        system_settings.get("session_cookie_secure", DEFAULTS["session_cookie_secure"])
    )
    app.config["SESSION_COOKIE_SAMESITE"] = system_settings.get(
        "session_cookie_samesite", DEFAULTS["session_cookie_samesite"])
    app.config["SESSION_COOKIE_HTTPONLY"] = bool(system_settings.get("session_cookie_httponly", DEFAULTS["session_cookie_httponly"]))
    app.config["SESSION_PERMANENT"] = bool(system_settings.get("session_permanent", DEFAULTS["session_permanent"]))
    app.config["REMEMBER_COOKIE_SECURE"] = bool(system_settings.get("remember_cookie_secure", DEFAULTS["remember_cookie_secure"]))
    app.config["REMEMBER_COOKIE_HTTPONLY"] = bool(system_settings.get("remember_cookie_httponly", DEFAULTS["remember_cookie_httponly"]))
    app.config["PREFERRED_URL_SCHEME"] = system_settings.get("preferred_url_scheme", DEFAULTS["preferred_url_scheme"])
    app.config["SESSION_REFRESH_EACH_REQUEST"] = bool(system_settings.get("session_refresh_each_request", DEFAULTS["session_refresh_each_request"]))
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=int(system_settings.get("permanent_session_lifetime", DEFAULTS["permanent_session_lifetime"])))
    
    # Allow the webserver (Apache / LiteSpeed) to serve large files using X-Sendfile
    # if mod_xsendfile (or equivalent) is enabled. 
    # Must be False in development/debug mode to avoid content length mismatch errors.
    is_dev = os.getenv("FLASK_ENV", "production") == "development"
    app.config["USE_X_SENDFILE"] = (os.getenv("USE_X_SENDFILE", "False").lower() == "true") and not is_dev

    # Initialize extensions
    cors.init_app(app, resources={r"/api/*": {"origins": get_allowed_cors_origins()}})
    csrf.init_app(app)
    limiter.init_app(app)

    # Security logging setup
    LOG_FILE = DATA_DIR / "security.log"
    try:
        LOG_FILE.parent.mkdir(exist_ok=True)
        LOG_FILE.touch(exist_ok=True)
    except Exception:
        logging.exception("Failed to create LOG_FILE in DATA_DIR; falling back to relative path")
    LOG_FILE_PATH = str(LOG_FILE.resolve())

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    file_handler_exists = False
    for h in list(root_logger.handlers):
        if isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == LOG_FILE_PATH:
            file_handler_exists = True
            break
    if not file_handler_exists:
        try:
            fh = logging.FileHandler(LOG_FILE_PATH)
            fh.setLevel(logging.INFO)
            fh.setFormatter(formatter)
            root_logger.addHandler(fh)
        except Exception:
            logging.exception("Could not open absolute LOG_FILE_PATH for writing; continuing with stream handler only")

    if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
        sh = logging.StreamHandler()
        sh.setLevel(logging.INFO)
        sh.setFormatter(formatter)
        root_logger.addHandler(sh)

    root_logger.info(f"Logging initialized. security log: {LOG_FILE_PATH}")

    # Register blueprints
    app.register_blueprint(main_bp)

    @app.before_request
    def limit_json_payload():
        if request.content_type == "application/json" and request.content_length:
            if request.content_length > MAX_JSON_SIZE:
                abort(413)

    @app.before_request
    def update_cors_origins():
        origins = get_allowed_cors_origins()
        cors.origins = origins

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        )
        return response

    return app
