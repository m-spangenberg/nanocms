from cerberus import Validator

stream_schema = {
    "access_token_required": {"type": "boolean", "required": False},
    "items": {"type": "list", "schema": {"type": "dict"}},
}


def validate_stream_json(data):
    """
    Validate the JSON data for a stream against the defined schema.
    
    :param data: The JSON data to validate
    :return: True if valid, False otherwise
    """
    v = Validator(stream_schema, allow_unknown=True)
    return v.validate(data)
