"""Keycloak OIDC 인증 모듈 (서비스 A, B 공통 코드)

흐름
1. /login            : 브라우저를 Keycloak 로그인 화면으로 보냄 (Authorization Code + PKCE)
2. /callback         : Keycloak이 돌려준 code를 토큰으로 교환하고, ID 토큰 서명을 검증한 뒤 로컬 세션 생성
3. /logout           : 로컬 세션 삭제 + Keycloak end_session_endpoint 호출 (SSO 세션까지 종료)
4. /backchannel-logout : 다른 서비스에서 로그아웃했을 때 Keycloak이 서버 대 서버로 알려주는 주소
"""
import os
import secrets
import time
from functools import wraps
from urllib.parse import urlencode

import jwt  # PyJWT: logout_token 서명 검증용
from authlib.integrations.flask_client import OAuth
from flask import Blueprint, abort, current_app, redirect, request, session, url_for

oauth = OAuth()
bp = Blueprint("auth", __name__)

# 서버 측 세션 저장소 {로컬 세션 ID: 사용자 정보}
# 브라우저 쿠키에는 로컬 세션 ID만 저장한다. 토큰은 서버 메모리에만 둔다.
SESSIONS: dict[str, dict] = {}

BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"
_jwks_clients: dict[str, jwt.PyJWKClient] = {}


def init_auth(app):
    oauth.init_app(app)
    oauth.register(
        name="keycloak",
        client_id=os.environ["CLIENT_ID"],
        client_secret=os.environ["CLIENT_SECRET"],
        server_metadata_url=os.environ["KEYCLOAK_ISSUER"] + "/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
    )
    app.register_blueprint(bp)
    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def check_csrf():
        # 폼 POST 요청은 세션에 저장된 CSRF 토큰과 일치해야 처리한다.
        # (Keycloak이 서버 대 서버로 보내는 백채널 로그아웃은 서명된 토큰으로 따로 검증)
        if request.method == "POST" and request.endpoint != "auth.backchannel_logout":
            expected = session.get("csrf")
            sent = request.form.get("csrf_token", "")
            if not expected or not secrets.compare_digest(expected, sent):
                abort(400, "CSRF 토큰이 올바르지 않습니다")


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def current_user():
    local_sid = session.get("local_sid")
    return SESSIONS.get(local_sid) if local_sid else None


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapper


def _safe_next(path):
    # 외부 사이트로 튕겨 나가는 open redirect 방지: 내부 경로만 허용
    if path and path.startswith("/") and not path.startswith("//"):
        return path
    return "/"


@bp.route("/login")
def login():
    session["next"] = _safe_next(request.args.get("next"))
    redirect_uri = os.environ["APP_URL"] + "/callback"
    return oauth.keycloak.authorize_redirect(redirect_uri)


@bp.route("/callback")
def callback():
    # code -> 토큰 교환. Authlib이 ID 토큰의 서명, issuer, audience, nonce를 검증한다.
    token = oauth.keycloak.authorize_access_token()
    claims = token["userinfo"]
    next_path = session.pop("next", "/")

    local_sid = secrets.token_urlsafe(32)
    SESSIONS[local_sid] = {
        "sub": claims["sub"],
        "username": claims.get("preferred_username"),
        "name": claims.get("name"),
        "display_name": claims.get("name") or claims.get("preferred_username"),
        "email": claims.get("email"),
        "kc_sid": claims.get("sid"),  # Keycloak SSO 세션 ID: A와 B에서 같게 나오면 SSO
        "auth_time": claims.get("auth_time"),  # 실제로 비밀번호를 입력한 시각
        "iat": claims.get("iat"),  # 이 서비스용 토큰이 발급된 시각
        "id_token": token["id_token"],
        "claims": dict(claims),
        "login_at": int(time.time()),
    }
    session.clear()
    session["local_sid"] = local_sid
    current_app.logger.info("로그인: %s (keycloak sid=%s)", claims.get("preferred_username"), claims.get("sid"))
    return redirect(next_path)


@bp.route("/logout")
def logout():
    user = current_user()
    SESSIONS.pop(session.get("local_sid"), None)
    session.clear()

    # Keycloak SSO 세션까지 종료 (RP-initiated logout)
    meta = oauth.keycloak.load_server_metadata()
    params = {
        "client_id": os.environ["CLIENT_ID"],
        "post_logout_redirect_uri": os.environ["APP_URL"] + "/",
    }
    if user:
        params["id_token_hint"] = user["id_token"]
    return redirect(meta["end_session_endpoint"] + "?" + urlencode(params))


@bp.route("/backchannel-logout", methods=["POST"])
def backchannel_logout():
    """Keycloak -> 서비스 서버로 직접 오는 로그아웃 통지 (브라우저를 거치지 않음)"""
    logout_token = request.form.get("logout_token")
    if not logout_token:
        abort(400)

    meta = oauth.keycloak.load_server_metadata()
    jwks_uri = meta["jwks_uri"]
    if jwks_uri not in _jwks_clients:
        _jwks_clients[jwks_uri] = jwt.PyJWKClient(jwks_uri)

    try:
        # Keycloak 공개키(JWKS)로 logout_token의 디지털 서명을 검증
        signing_key = _jwks_clients[jwks_uri].get_signing_key_from_jwt(logout_token).key
        claims = jwt.decode(
            logout_token,
            signing_key,
            algorithms=["RS256", "ES256"],
            audience=os.environ["CLIENT_ID"],
            issuer=meta["issuer"],
        )
    except jwt.PyJWTError as e:
        current_app.logger.warning("logout_token 검증 실패: %s", e)
        abort(400)

    if BACKCHANNEL_EVENT not in claims.get("events", {}):
        abort(400)

    kc_sid, sub = claims.get("sid"), claims.get("sub")
    targets = [
        k for k, v in SESSIONS.items()
        if (kc_sid and v["kc_sid"] == kc_sid) or (not kc_sid and v["sub"] == sub)
    ]
    for k in targets:
        del SESSIONS[k]
    current_app.logger.info("백채널 로그아웃: keycloak sid=%s, 삭제된 로컬 세션 %d개", kc_sid, len(targets))
    return "", 200
