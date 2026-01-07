import json
import logging
import secrets
import shutil
from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
    current_app,
    make_response,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from auth import get_access_token, is_logged_in, verify_token
from config import (
    APP_ROOT,
    DATA_DIR,
    DEFAULTS,
    FIRST_START_FILE,
    PASSWORD_HASH_FILE,
    UPLOAD_FOLDER,
    load_settings,
    save_settings,
)
from storage import get_streams
from utils import allowed_file

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """
    Sends the user to the dashboard if logged in, otherwise to the login page.
    """
    return (
        redirect(url_for("main.dashboard"))
        if is_logged_in()
        else redirect(url_for("main.login"))
    )


@main_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Logs the user in. If it's the first start, requires a password change.
    """
    # Check if first start: require password change
    require_pw_change = FIRST_START_FILE.exists()
    if request.method == "POST":
        username = request.form["username"]
        if username != "admin":
            flash("Invalid credentials", "danger")
            return render_template("login.html", require_pw_change=require_pw_change)
        password = request.form["password"]
        # Only one admin user, username can be anything or set in env
        with open(PASSWORD_HASH_FILE) as f:
            pw_hash = f.read().strip()
        if check_password_hash(pw_hash, password):
            session["logged_in"] = True
            if require_pw_change:
                session["require_pw_change"] = True
                return redirect(url_for("main.set_password"))
            return redirect(url_for("main.dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("login.html", require_pw_change=require_pw_change)


@main_bp.route("/set-password", methods=["GET", "POST"])
def set_password():
    """
    Sets a new password for the user.
    """
    if not session.get("logged_in") or not session.get("require_pw_change"):
        return redirect(url_for("main.login"))
    if request.method == "POST":
        new_pw = request.form["new_password"]
        confirm_pw = request.form["confirm_password"]
        if not new_pw or len(new_pw) < 8:
            flash("Password must be at least 8 characters.", "danger")
        elif new_pw != confirm_pw:
            flash("Passwords do not match.", "danger")
        else:
            pw_hash = generate_password_hash(new_pw)
            with open(PASSWORD_HASH_FILE, "w") as f:
                f.write(pw_hash)
            if FIRST_START_FILE.exists():
                FIRST_START_FILE.unlink()
            session.pop("require_pw_change", None)
            flash("Password updated. Please log in again.", "success")
            session.clear()
            return redirect(url_for("main.login"))
    return render_template("set_password.html")


@main_bp.route("/logout")
def logout():
    """
    Logs the user out.
    """
    session.clear()
    return redirect(url_for("main.login"))


@main_bp.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if not is_logged_in():
        return redirect(url_for("main.login"))

    # Add stream
    if request.method == "POST" and "add_stream" in request.form:
        new_stream = request.form["add_stream"].strip()
        if not new_stream:
            flash("Stream name cannot be empty.", "danger")
        else:
            safe_name = secure_filename(new_stream)
            if not safe_name:
                flash("Invalid stream name.", "danger")
            else:
                json_path = (DATA_DIR / f"{safe_name}.json").resolve()
                upload_path = (UPLOAD_FOLDER / safe_name).resolve()
                try:
                    # Ensure both are inside app root
                    json_path.relative_to(APP_ROOT)
                    upload_path.relative_to(APP_ROOT)
                except ValueError:
                    flash("Invalid stream name/path.", "danger")
                    return redirect(url_for("main.dashboard"))
                if json_path.exists():
                    flash("A stream with that name already exists.", "danger")
                else:
                    json_path.write_text("[]")
                    upload_path.mkdir(exist_ok=True, parents=True)
                    flash(f"Stream '{safe_name}' created.", "success")
        return redirect(url_for("main.dashboard"))

    # Remove stream
    if request.method == "POST" and "remove_stream" in request.form:
        stream = request.form["remove_stream"]
        json_path = (DATA_DIR / f"{stream}.json").resolve()
        upload_path = (UPLOAD_FOLDER / stream).resolve()
        try:
            json_path.relative_to(APP_ROOT)
            upload_path.relative_to(APP_ROOT)
        except ValueError:
            flash("Invalid stream name/path.", "danger")
            return redirect(url_for("main.dashboard"))
        if json_path.exists():
            json_path.unlink()
        if upload_path.exists():
            shutil.rmtree(upload_path)
        flash(f"Stream '{stream}' deleted.", "success")
        return redirect(url_for("main.dashboard"))

    # Rename stream
    if request.method == "POST" and "rename_stream" in request.form:
        old = request.form["rename_stream"]
        new = request.form["new_stream_name"].strip()
        safe_new = secure_filename(new)
        old_json = (DATA_DIR / f"{old}.json").resolve()
        new_json = (DATA_DIR / f"{safe_new}.json").resolve()
        old_upload = (UPLOAD_FOLDER / old).resolve()
        new_upload = (UPLOAD_FOLDER / safe_new).resolve()
        try:
            old_json.relative_to(APP_ROOT)
            new_json.relative_to(APP_ROOT)
            old_upload.relative_to(APP_ROOT)
            new_upload.relative_to(APP_ROOT)
        except ValueError:
            flash("Invalid stream name/path.", "danger")
            return redirect(url_for("main.dashboard"))
        if not safe_new:
            flash("Invalid new stream name.", "danger")
        elif not old_json.exists():
            flash("Original stream does not exist.", "danger")
        elif new_json.exists():
            flash("A stream with that name already exists.", "danger")
        else:
            old_json.rename(new_json)
            if old_upload.exists():
                old_upload.rename(new_upload)
            flash(f"Stream '{old}' renamed to '{safe_new}'.", "success")
        return redirect(url_for("main.dashboard"))

    streams = get_streams()
    # Count uploaded files for each stream
    stream_upload_counts = {}
    for stream in streams:
        upload_dir = (UPLOAD_FOLDER / stream).resolve()
        try:
            upload_dir.relative_to(APP_ROOT)
        except ValueError:
            stream_upload_counts[stream] = 0
            continue
        if upload_dir.exists():
            stream_upload_counts[stream] = sum(
                1 for f in upload_dir.iterdir() if f.is_file()
            )
        else:
            stream_upload_counts[stream] = 0
    return render_template(
        "dashboard.html", streams=streams, stream_upload_counts=stream_upload_counts
    )


@main_bp.route("/edit/<stream>", methods=["GET", "POST"])
def edit_stream(stream):
    if not is_logged_in():
        return redirect(url_for("main.login"))

    filepath = (DATA_DIR / f"{stream}.json").resolve()
    if not filepath.exists() or not filepath.relative_to(APP_ROOT):
        return "Stream not found", 404

    # Ensure per-stream upload folder exists
    stream_upload_folder = (UPLOAD_FOLDER / stream).resolve()
    try:
        stream_upload_folder.relative_to(APP_ROOT)
    except ValueError:
        return "Invalid stream path", 400
    stream_upload_folder.mkdir(exist_ok=True, parents=True)

    # Handle file upload
    if request.method == "POST":
        if "file" in request.files:
            file = request.files["file"]
            if file and allowed_file(file.filename):
                filename = file.filename
                save_path = (stream_upload_folder / filename).resolve()
                try:
                    save_path.relative_to(stream_upload_folder)
                except ValueError:
                    flash("Invalid file path.", "danger")
                    return redirect(url_for("main.edit_stream", stream=stream))
                file.save(save_path)
                flash(f"File uploaded: {filename}", "success")
            elif file and file.filename:
                flash("Invalid file type.", "danger")
        # Handle JSON data update
        try:
            data = json.loads(request.form["data"])
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
            flash("Saved successfully", "success")
        except Exception as e:
            flash(f"Error saving data: {e}", "danger")

    # List uploaded files for this stream
    uploaded_files = []
    if stream_upload_folder.exists():
        uploaded_files = [f.name for f in stream_upload_folder.iterdir() if f.is_file()]

    with open(filepath) as f:
        current_data = f.read()

    return render_template(
        "edit.html",
        stream=stream,
        data=current_data,
        uploaded_files=uploaded_files,
    )


@main_bp.route("/uploads/<stream>/<filename>", methods=["GET"])
def uploaded_file(stream, filename):
    import re

    # Validate stream and filename
    if not re.match(r"^[\w\-]+$", stream):
        return "Invalid stream name", 400
    if not allowed_file(filename):
        return "Invalid filename", 400

    file_path = (UPLOAD_FOLDER / stream / filename).resolve()
    try:
        file_path.relative_to(APP_ROOT)
    except ValueError:
        return "Invalid file path", 400

    # Check if access_token_required is set for this stream
    json_path = (DATA_DIR / f"{stream}.json").resolve()
    access_token_required = False
    if json_path.exists():
        with open(json_path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            access_token_required = data.get("access_token_required", False)
        elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            access_token_required = data[0].get("access_token_required", False)

    # Enforce HTTPS for token-protected endpoints
    if access_token_required and not request.is_secure and not is_logged_in():
        return "HTTPS required for token-protected uploads", 403

    if access_token_required and not is_logged_in():
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return "Missing or invalid Authorization header", 401
        token = auth_header[7:]
        from application import secret_key
        if not verify_token(token, secret_key):
            return "Unauthorized", 403
        logging.info(
            f"File access: {filename} in {stream} by token {token} from {request.remote_addr}"
        )
    elif is_logged_in():
        logging.info(
            f"File access: {filename} in {stream} by admin from {request.remote_addr}"
        )

    # If configured, prefer offloading file transfer to the webserver via X-Sendfile
    file_path = (UPLOAD_FOLDER / stream / filename).resolve()
    if current_app.config.get("USE_X_SENDFILE"):
        # Add both common X-Sendfile and LiteSpeed header variants to support different hosts
        resp = make_response("")
        resp.headers["X-Sendfile"] = str(file_path)
        # LiteSpeed/CloudLinux sometimes recognizes X-LiteSpeed-Location
        resp.headers["X-LiteSpeed-Location"] = str(file_path)
        # Provide a minimal content-disposition so browsers treat it as a download
        resp.headers["Content-Disposition"] = f"attachment; filename=\"{filename}\""
        # Let the webserver set the proper Content-Type
        return resp

    return send_from_directory((UPLOAD_FOLDER / stream).resolve(), filename)


@main_bp.route("/uploads/<stream>/<filename>/delete", methods=["POST"])
def delete_uploaded_file(stream, filename):
    import re

    if not is_logged_in():
        return redirect(url_for("main.login"))
    # Validate stream and filename
    if not re.match(r"^[\w\-]+$", stream):
        flash("Invalid stream name.", "danger")
        return redirect(url_for("main.edit_stream", stream=stream))
    if not allowed_file(filename):
        flash("Invalid filename.", "danger")
        return redirect(url_for("main.edit_stream", stream=stream))
    file_path = (UPLOAD_FOLDER / stream / filename).resolve()
    try:
        file_path.relative_to(APP_ROOT)
    except ValueError:
        flash("Invalid file path.", "danger")
        return redirect(url_for("edit_stream", stream=stream))
    if file_path.exists():
        file_path.unlink()
        logging.info(
            f"Deleted file: {filename} in {stream} by admin from {request.remote_addr}"
        )
        flash(f"Deleted file: {filename}", "success")
    else:
        flash("File not found.", "danger")
    return redirect(url_for("main.edit_stream", stream=stream))


@main_bp.route("/api/v1/<stream>")
def api_stream(stream):
    filepath = (DATA_DIR / f"{stream}.json").resolve()
    try:
        filepath.relative_to(APP_ROOT)
    except ValueError:
        return jsonify({"error": "Invalid stream path"}), 400
    if not filepath.exists():
        return jsonify({"error": "Stream not found"}), 404

    with open(filepath) as f:
        data = json.load(f)

    # Check if access_token_required is set
    access_token_required = False
    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
        access_token_required = data[0].get("access_token_required", False)
    elif isinstance(data, dict):
        access_token_required = data.get("access_token_required", False)

    if access_token_required:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth_header[7:]
        from application import secret_key
        if not verify_token(token, secret_key):
            return jsonify({"error": "Unauthorized"}), 403

    return jsonify(data)


def handle_api_token_form(request, session):
    if "regenerate_token" in request.form:
        token = secrets.token_urlsafe(24)
        from auth import store_token_hash

        store_token_hash(token)
        session["show_api_token_once"] = token
        flash(
            "New API access token generated. Please copy it now; it will not be shown again.",
            "success",
        )
        return redirect(url_for("main.settings"))
    return None


def handle_password_form(request):
    if "change_password" in request.form:
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")
        with open(PASSWORD_HASH_FILE) as f:
            pw_hash = f.read().strip()
        if not check_password_hash(pw_hash, current_pw):
            flash("Current password is incorrect.", "danger")
        elif not new_pw or len(new_pw) < 8:
            flash("New password must be at least 8 characters.", "danger")
        elif new_pw != confirm_pw:
            flash("New passwords do not match.", "danger")
        else:
            new_hash = generate_password_hash(new_pw)
            with open(PASSWORD_HASH_FILE, "w") as f:
                f.write(new_hash)
            flash("Password changed successfully.", "success")
            return redirect(url_for("main.settings"))
    return None


def handle_general_settings_form(request, settings):
    if (
        "allowed_cors_origins" in request.form
        or "max_content_length" in request.form
        or "max_json_size" in request.form
        or "allowed_extensions" in request.form
    ):
        raw_origins = request.form.get("allowed_cors_origins", "*")
        origins = [
            o.strip()
            for o in raw_origins.replace("\r", "").replace("\n", ",").split(",")
            if o.strip()
        ]
        settings["allowed_cors_origins"] = origins
        settings["max_content_length"] = int(
            request.form.get("max_content_length", DEFAULTS["max_content_length"])
        )
        settings["max_json_size"] = int(
            request.form.get("max_json_size", DEFAULTS["max_json_size"])
        )
        settings["allowed_extensions"] = [
            e.strip().lower()
            for e in request.form.get("allowed_extensions", "").split(",")
            if e.strip()
        ]
        save_settings(settings)
        flash("General settings updated!", "success")
        return redirect(url_for("main.settings"))
    return None


def handle_security_settings_form(request, settings):
    if (
        "session_cookie_secure" in request.form
        or "session_cookie_samesite" in request.form
    ):
        settings["session_cookie_secure"] = (
            request.form.get("session_cookie_secure") == "on"
        )
        settings["session_cookie_samesite"] = request.form.get(
            "session_cookie_samesite", DEFAULTS["session_cookie_samesite"]
        )
        save_settings(settings)
        flash("Security settings updated!", "success")
        return redirect(url_for("main.settings"))
    return None


@main_bp.route("/settings", methods=["GET", "POST"])
def settings():
    if not is_logged_in():
        return redirect(url_for("main.login"))
    settings = load_settings()

    # Handle POST forms
    if request.method == "POST":
        for handler in [
            lambda: handle_api_token_form(request, session),
            lambda: handle_password_form(request),
            lambda: handle_general_settings_form(request, settings),
            lambda: handle_security_settings_form(request, settings),
        ]:
            result = handler()
            if result is not None:
                return result

    # Prepare allowed_cors_origins for textarea display
    allowed_cors_origins = settings.get(
        "allowed_cors_origins", DEFAULTS["allowed_cors_origins"]
    )
    if isinstance(allowed_cors_origins, list):
        allowed_cors_origins = "\n".join(allowed_cors_origins)
    allowed_extensions = ", ".join(
        settings.get("allowed_extensions", DEFAULTS["allowed_extensions"])
    )
    api_access_token = None
    if session.get("show_api_token_once"):
        api_access_token = session.pop("show_api_token_once")

    return render_template(
        "settings.html",
        allowed_cors_origins=allowed_cors_origins,
        max_content_length=settings.get(
            "max_content_length", DEFAULTS["max_content_length"]
        ),
        max_json_size=settings.get("max_json_size", DEFAULTS["max_json_size"]),
        allowed_extensions=allowed_extensions,
        session_cookie_secure=settings.get(
            "session_cookie_secure", DEFAULTS["session_cookie_secure"]
        ),
        session_cookie_samesite=settings.get(
            "session_cookie_samesite", DEFAULTS["session_cookie_samesite"]
        ),
        api_access_token=api_access_token,
    )


@main_bp.route("/help")
def help_view():
    if not is_logged_in():
        return redirect(url_for("main.login"))
    return render_template("help.html")


# Flask error handlers for consistent error responses
@main_bp.errorhandler(400)
def bad_request(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": str(e)}), 400
    return render_template("error.html", error=str(e)), 400


@main_bp.errorhandler(401)
def unauthorized(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": str(e)}), 401
    return render_template("error.html", error=str(e)), 401


@main_bp.errorhandler(403)
def forbidden(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": str(e)}), 403
    return render_template("error.html", error=str(e)), 403


@main_bp.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": str(e)}), 404
    return render_template("error.html", error=str(e)), 404


@main_bp.errorhandler(500)
def server_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error"}), 500
    return render_template("error.html", error="Internal server error"), 500
