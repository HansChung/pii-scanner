from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge

from .auth import auth
from .config import Config
from .db import close_db, init_db
from .routes import api
from .scanner import cleanup_stale_uploads


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder="../static/app",
        static_url_path="/app",
        instance_relative_config=True,
    )
    app.config.from_object(Config())
    CORS(app, resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}})

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["TEMP_UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)

    with app.app_context():
        init_db()
        cleanup_stale_uploads()

    app.teardown_appcontext(close_db)
    app.register_blueprint(api, url_prefix="/api")
    app.register_blueprint(auth, url_prefix="/auth")

    @app.errorhandler(RequestEntityTooLarge)
    def handle_large_file(_: RequestEntityTooLarge):
        return (
            jsonify(
                {
                    "error": "file_too_large",
                    "message": "檔案過大，請先分檔後重新上傳。",
                    "maxFileMb": app.config["MAX_FILE_MB"],
                }
            ),
            413,
        )

    @app.get("/")
    def index():
        index_path = Path(app.static_folder or "") / "index.html"
        if index_path.exists():
            return send_from_directory(app.static_folder, "index.html")
        return jsonify({"name": "school-pii-checker", "status": "frontend_not_built"})

    @app.get("/<path:path>")
    def spa(path: str):
        static_folder = Path(app.static_folder or "")
        requested = static_folder / path
        if requested.exists() and requested.is_file():
            return send_from_directory(static_folder, path)
        if (static_folder / "index.html").exists():
            return send_from_directory(static_folder, "index.html")
        return jsonify({"error": "not_found"}), 404

    return app
