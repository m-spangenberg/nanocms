import re
from config import get_allowed_extensions


def allowed_file(filename):
    """
    Check if the uploaded file has an allowed extension and a safe filename.
    
    :param filename: The name of the file to check
    :return: True if the file is allowed, False otherwise
    """
    safe = re.match(r"^[\w\-.]+$", filename)
    ext_ok = (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in get_allowed_extensions()
    )
    return safe and ext_ok
