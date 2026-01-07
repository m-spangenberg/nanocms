import json
from config import DATA_DIR, UPLOAD_FOLDER


def get_streams():
    """
    Get a list of all available streams by scanning the DATA_DIR for JSON files.
    """
    return [f.stem for f in DATA_DIR.glob("*.json")]


def get_stream_json_path(stream):
    """
    Get the file path for a given stream's JSON data.

    :param stream: The name of the stream
    """
    return (DATA_DIR / f"{stream}.json").resolve()


def get_stream_upload_path(stream):
    """
    Get the upload folder path for a given stream.
    
    "param stream: The name of the stream
    """
    return (UPLOAD_FOLDER / stream).resolve()


def read_stream_data(stream):
    """
    Read the JSON data for a given stream.

    :param stream: The name of the stream
    """
    path = get_stream_json_path(stream)
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None


def write_stream_data(stream, data):
    """
    Write JSON data to a given stream.

    :param stream: The name of the stream
    :param data: The JSON-serializable data to write
    """
    path = get_stream_json_path(stream)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
