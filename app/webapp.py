# ShadowTrap - deceptive web application (victim side).
# Run from project root:
#   python -m app.webapp
# Serves on:
#   http://127.0.0.1:5000

import os
import uuid

from flask import (
    Flask,
    request,
    render_template,
    redirect,
    make_response,
    Response,
    jsonify,
)

try:
    from .db import init_db
    from .detector import log_event
except ImportError:
    from db import init_db
    from detector import log_event


# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
TEMPLATE_DIR = os.path.join(PROJECT_DIR, "templates")
STATIC_DIR = os.path.join(PROJECT_DIR, "static")


# ---------------------------------------------------------
# Deception configuration
# ---------------------------------------------------------

HONEYKEY = "SHADOW-7F92-4C1A-B8E3"


# ---------------------------------------------------------
# Flask application
# ---------------------------------------------------------

def create_app():

    app = Flask(
        __name__,
        template_folder=TEMPLATE_DIR,
        static_folder=STATIC_DIR,
        static_url_path="/static",
    )

    # Initialize SQLite database
    init_db()

    # -----------------------------------------------------
    # Event logging helper
    # -----------------------------------------------------

    def log(event_type, detail=""):

        # Reuse visitor session cookie if available.
        # Otherwise create a new session ID.
        sid = request.cookies.get("sid") or uuid.uuid4().hex[:12]

        log_event(
            ip=request.remote_addr or "127.0.0.1",
            sid=sid,
            method=request.method,
            path=request.path,
            event_type=event_type,
            detail=detail,
            ua=request.headers.get("User-Agent", ""),
        )

        return sid

    # -----------------------------------------------------
    # HTML response helper
    # -----------------------------------------------------

    def finish_html(html, sid, status=200):

        resp = make_response(
            Response(
                html,
                status=status,
                mimetype="text/html",
            )
        )

        resp.set_cookie(
            "sid",
            sid,
            httponly=True,
            samesite="Lax",
        )

        return resp

    # =====================================================
    # NORMAL PUBLIC WEBSITE
    # =====================================================

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route("/robots.txt")
    def robots():

        return Response(
            "User-agent: *\n"
            "Disallow: /admin-backup\n",
            mimetype="text/plain",
        )

    # =====================================================
    # DECEPTION LAYER 1
    # Hidden / Shadow Route
    # =====================================================

    @app.route("/admin-backup")
    def shadow_root():

        sid = log("hidden_route")

        # Attacker receives a normal-looking 404 page.
        # The upgraded 404 page should NOT reveal the hidden
        # route directly.
        return finish_html(
            render_template("404.html"),
            sid,
            status=404,
        )

    # =====================================================
    # DECEPTION LAYER 2
    # Phantom Login
    # =====================================================

    @app.route("/admin-backup/login", methods=["GET"])
    def phantom_login():

        sid = log(
            "hidden_route",
            detail="phantom login page discovered",
        )

        return finish_html(
            render_template("login.html"),
            sid,
        )

    @app.route("/admin-backup/login", methods=["POST"])
    def phantom_login_submit():

        username = request.form.get("username", "")

        # IMPORTANT:
        # We never store/log the password.
        sid = log(
            "credential_probe",
            detail="username=" + username,
        )

        # Any credentials appear to work because this is
        # a deceptive environment.
        resp = make_response(
            redirect("/admin-backup/panel")
        )

        resp.set_cookie(
            "sid",
            sid,
            httponly=True,
            samesite="Lax",
        )

        return resp

    # =====================================================
    # Phantom Administration Panel
    # =====================================================

    @app.route("/admin-backup/panel")
    def phantom_panel():

        sid = log("panel_access")

        return finish_html(
            render_template(
                "panel.html",
                api_key=HONEYKEY,
            ),
            sid,
        )

    # =====================================================
    # DECEPTION LAYER 3
    # Honeytoken API Key
    # =====================================================

    @app.route("/api/v1/users")
    def api_users():

        key = request.args.get("key", "")

        if key == HONEYKEY:

            sid = log(
                "honeytoken",
                detail="decoy key used: " + key,
            )

            data = {
                "users": [
                    {
                        "id": 1,
                        "name": "John Doe",
                        "email": "john@example.com",
                    },
                    {
                        "id": 2,
                        "name": "Jane Smith",
                        "email": "jane@example.com",
                    },
                ]
            }

            resp = make_response(
                jsonify(data),
                200,
            )

            resp.set_cookie(
                "sid",
                sid,
                httponly=True,
                samesite="Lax",
            )

            return resp

        return jsonify(
            {"error": "invalid api key"}
        ), 401

    # =====================================================
    # DECEPTION LAYER 4
    # Phantom Sensitive Files
    # =====================================================

    DECOYS = {

        "/database_backup.sql": (
            "-- ShadowMart database backup (dump)\n"
            "CREATE TABLE users("
            "id INTEGER, "
            "username TEXT, "
            "password_hash TEXT"
            ");\n"
            "INSERT INTO users VALUES "
            "(1,'admin',"
            "'5f4dcc3b5aa765d61d8327deb882cf99');\n"
        ),

        "/customer_records.csv": (
            "id,name,email,phone\n"
            "1,John Doe,john@example.com,555-0101\n"
            "2,Jane Smith,jane@example.com,555-0102\n"
        ),

        "/admin_notes.txt": (
            "Admin notes:\n"
            "- Remember to rotate the backup API key "
            "before Friday.\n"
            "- Latest database dump: "
            "/database_backup.sql\n"
        ),
    }

    # -----------------------------------------------------
    # Register deceptive file routes
    # -----------------------------------------------------

    for path, content in DECOYS.items():

        def decoy(content=content):

            sid = log("decoy_file")

            resp = make_response(
                Response(
                    content,
                    mimetype="text/plain",
                )
            )

            resp.set_cookie(
                "sid",
                sid,
                httponly=True,
                samesite="Lax",
            )

            return resp

        app.add_url_rule(
            path,
            "decoy_" + path.strip("/").replace("/", "_"),
            decoy,
        )

    # -----------------------------------------------------
    # Return configured Flask app
    # -----------------------------------------------------

    return app


# =========================================================
# Application entry point
# =========================================================

app = create_app()


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )