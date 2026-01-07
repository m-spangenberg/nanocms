import yaml
from pathlib import Path

DEFAULTS = {
    "max_content_length": 10,  # MB
    "max_json_size": 1,  # MB
    "allowed_extensions": ["png", "jpg", "jpeg", "pdf"],
    "session_cookie_secure": True,
    "session_cookie_samesite": "Strict",
    "session_cookie_httponly": True,
    "session_permanent": False,
    "remember_cookie_secure": True,
    "remember_cookie_httponly": True,
    "preferred_url_scheme": "https",
    "session_refresh_each_request": True,
    "permanent_session_lifetime": 3600,  # seconds (1 hour)
    "allowed_cors_origins": ["*"],
}

APP_ROOT = Path(__file__).parent.resolve()
DATA_DIR = (APP_ROOT / "data").resolve()
UPLOAD_FOLDER = (APP_ROOT / "static/uploads").resolve()
SETTINGS_FILE = DATA_DIR / "settings.yaml"
PASSWORD_HASH_FILE = DATA_DIR / "admin_pw_hash.txt"
ACCESS_TOKEN_FILE = DATA_DIR / "access_token.txt"
FIRST_START_FILE = DATA_DIR / "first_start_pw.txt"


def load_settings():
    """
    Load settings from the SETTINGS_FILE, applying defaults where necessary.
    """
    if SETTINGS_FILE.exists():
        with open(SETTINGS_FILE, "r") as f:
            settings = yaml.safe_load(f) or {}
    else:
        settings = {}
    for k, v in DEFAULTS.items():
        if k not in settings:
            settings[k] = v
    return settings


def save_settings(settings):
    """
    Save settings to the SETTINGS_FILE.

    :param settings: The settings dictionary to save
    """
    with open(SETTINGS_FILE, "w") as f:
        yaml.safe_dump(settings, f)


def get_allowed_cors_origins():
    """
    Get the list of allowed CORS origins from settings.

    :return: A list of allowed CORS origins
    """
    settings = load_settings()
    origins = settings.get("allowed_cors_origins", DEFAULTS["allowed_cors_origins"])
    if isinstance(origins, str):
        origins = [o.strip() for o in origins.split(",") if o.strip()]
    return origins


def get_allowed_extensions():
    """
    Get the set of allowed file extensions from settings.

    :return: A set of allowed file extensions
    """
    settings = load_settings()
    exts = settings.get("allowed_extensions", DEFAULTS["allowed_extensions"])
    if isinstance(exts, str):
        exts = [e.strip().lower() for e in exts.split(",") if e.strip()]
    return set(exts)
