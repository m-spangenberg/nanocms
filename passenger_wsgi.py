import os
import sys
import traceback

# Ensure project root is on path so relative imports work when Passenger imports this file
project_dir = os.path.dirname(__file__)
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)


# Fail fast if the host Python is older than the app requires.
# Your pyproject specifies Python >=3.11; many shared hosts default to older Pythons
# (the stacktrace you showed referenced Python 3.6). Passenger will otherwise repeatedly
# re-import this module and produce long, noisy traces in logs.
MIN_PYTHON = (3, 11)
if sys.version_info < MIN_PYTHON:
    msg = (
        f"ERROR: Python {sys.version_info.major}.{sys.version_info.minor} detected. "
        f"This application requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+. "
        "Please select Python 3.11 (or newer) in your Namecheap Application Manager.\n"
    )
    # Write a short, clear message to stderr and stop import to avoid repeating long traces
    sys.stderr.write(msg)
    raise SystemExit(1)


# Import the Flask application object from your application module.
# Passenger expects a WSGI callable named `application` in this module.
try:
    from application import app as application
except Exception:
    sys.stderr.write("Failed to import WSGI application from 'application.py'. See traceback:\n")
    traceback.print_exc(file=sys.stderr)
    # Re-raise to let Passenger see the failure (but we already printed a concise message)
    raise
