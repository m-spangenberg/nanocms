import json
from config import DATA_DIR, UPLOAD_FOLDER


def get_streams():
    return [f.stem for f in DATA_DIR.glob("*.json")]


def get_stream_json_path(stream):
    return (DATA_DIR / f"{stream}.json").resolve()


def get_stream_upload_path(stream):
    return (UPLOAD_FOLDER / stream).resolve()


def read_stream_data(stream):
    path = get_stream_json_path(stream)
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None


def write_stream_data(stream, data):
    path = get_stream_json_path(stream)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
