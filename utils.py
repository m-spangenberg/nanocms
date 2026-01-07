import re
from config import get_allowed_extensions


def allowed_file(filename):
    safe = re.match(r"^[\w\-.]+$", filename)
    ext_ok = (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in get_allowed_extensions()
    )
    return safe and ext_ok
