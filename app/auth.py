from __future__ import annotations

import functools
import uuid
from typing import Any, Callable, TypeVar

import msal
from flask import Blueprint, current_app, jsonify, redirect, request, session, url_for

auth = Blueprint("auth", __name__)
F = TypeVar("F", bound=Callable[..., Any])


def _msal_app() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        current_app.config["MS_CLIENT_ID"],
        authority=current_app.config["MS_AUTHORITY"],
        client_credential=current_app.config["MS_CLIENT_SECRET"],
    )


def _redirect_uri() -> str:
    return url_for("auth.callback", _external=True)


def auth_configured() -> bool:
    return bool(current_app.config["MS_CLIENT_ID"] and current_app.config["MS_CLIENT_SECRET"])


def current_user() -> dict[str, Any] | None:
    return session.get("user")


def current_user_name() -> str:
    user = current_user() or {}
    return str(user.get("email") or user.get("name") or "anonymous")


def is_admin() -> bool:
    if not current_app.config["AUTH_REQUIRED"]:
        return True
    admins = current_app.config["ADMIN_EMAILS"]
    if not admins:
        return bool(current_user())
    user = current_user() or {}
    return str(user.get("email", "")).lower() in admins


def login_required(func: F) -> F:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any):
        if not current_app.config["AUTH_REQUIRED"]:
            return func(*args, **kwargs)
        if current_user():
            return func(*args, **kwargs)
        return jsonify({"error": "unauthorized", "message": "請先使用 Microsoft 365 帳號登入。"}), 401

    return wrapper  # type: ignore[return-value]


def admin_required(func: F) -> F:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any):
        auth_result = login_required(lambda: None)()
        if auth_result is not None:
            return auth_result
        if is_admin():
            return func(*args, **kwargs)
        return jsonify({"error": "forbidden", "message": "你沒有管理後台權限。"}), 403

    return wrapper  # type: ignore[return-value]


@auth.get("/login")
def login():
    if not auth_configured():
        return jsonify({"error": "auth_not_configured", "message": "尚未設定 Microsoft 365 登入。"}), 503
    state = str(uuid.uuid4())
    session["auth_state"] = state
    url = _msal_app().get_authorization_request_url(
        scopes=current_app.config["MS_SCOPES"],
        state=state,
        redirect_uri=_redirect_uri(),
        prompt="select_account",
    )
    return redirect(url)


@auth.get("/callback")
def callback():
    if request.args.get("state") != session.get("auth_state"):
        return jsonify({"error": "invalid_state", "message": "登入狀態驗證失敗，請重新登入。"}), 400
    if "error" in request.args:
        return (
            jsonify(
                {
                    "error": request.args.get("error"),
                    "message": request.args.get("error_description", "Microsoft 登入失敗。"),
                }
            ),
            400,
        )
    result = _msal_app().acquire_token_by_authorization_code(
        request.args.get("code", ""),
        scopes=current_app.config["MS_SCOPES"],
        redirect_uri=_redirect_uri(),
    )
    if "error" in result:
        return (
            jsonify(
                {
                    "error": result.get("error"),
                    "message": result.get("error_description", "無法取得 Microsoft 登入權杖。"),
                }
            ),
            400,
        )
    claims = result.get("id_token_claims", {})
    session["user"] = {
        "name": claims.get("name", ""),
        "email": claims.get("preferred_username") or claims.get("email") or claims.get("upn") or "",
        "tenantId": claims.get("tid", ""),
        "objectId": claims.get("oid", ""),
    }
    session.pop("auth_state", None)
    return redirect("/")


@auth.get("/logout")
def logout():
    session.clear()
    post_logout = url_for("index", _external=True)
    return redirect(f"{current_app.config['MS_AUTHORITY']}/oauth2/v2.0/logout?post_logout_redirect_uri={post_logout}")
