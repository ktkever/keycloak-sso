"""서비스 B: 팀 일정 캘린더 (포트 3002)

- 월간 달력, 일정 등록/수정/삭제 (작성자 본인만 수정·삭제)
- 다가오는 일정 목록, 카테고리별 색상
- 보안 도구: ID 토큰 분석(/token), ECDSA 서명 직접 검증(/ecdsa) ← 가점 #2
- 데이터는 SQLite(data.db)에 저장
"""
import calendar
import datetime as dt
import json
import os
import sqlite3
import time
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).parent
load_dotenv(BASE_DIR / ".env")

import jwt  # noqa: E402
import requests  # noqa: E402
from flask import Flask, abort, flash, g, redirect, render_template, request, url_for  # noqa: E402

import ecdsa_manual  # noqa: E402
from auth import current_user, init_auth, login_required, oauth  # noqa: E402

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config["SESSION_COOKIE_NAME"] = "session_service_b"
init_auth(app)

DB_PATH = os.environ.get("DB_PATH", str(BASE_DIR / "data.db"))
CATEGORIES = {"회의": "#6366f1", "마감": "#ef4444", "행사": "#f59e0b", "개인": "#10b981", "기타": "#64748b"}
WEEKDAYS = ["일", "월", "화", "수", "목", "금", "토"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    date TEXT NOT NULL,          -- YYYY-MM-DD
    start_time TEXT,             -- HH:MM, 비어 있으면 종일
    end_time TEXT,
    category TEXT NOT NULL,
    location TEXT,
    memo TEXT,
    author_sub TEXT NOT NULL,
    author_name TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_date ON events(date);
"""


# ── DB ──────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


with sqlite3.connect(DB_PATH) as conn:
    conn.executescript(SCHEMA)


# ── 템플릿 공통 ─────────────────────────────────────────────────────
@app.template_filter("ts")
def format_ts(t):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "-"


@app.template_filter("hex")
def to_hex(n):
    return f"0x{n:064x}" if isinstance(n, int) else "-"


@app.template_filter("kdate")
def korean_date(s):
    d = dt.date.fromisoformat(s)
    return f"{d.month}월 {d.day}일 ({WEEKDAYS[(d.weekday() + 1) % 7]})"


@app.context_processor
def inject_common():
    return {
        "user": current_user(),
        "other_service": {"name": "TeamBoard 게시판", "url": os.environ["OTHER_SERVICE_URL"]},
        "security_links": [
            {"name": "ID 토큰 분석", "url": url_for("token_page"), "desc": "Keycloak이 발급한 JWT의 헤더와 클레임"},
            {"name": "ECDSA 서명 직접 검증", "url": url_for("ecdsa_page"), "desc": "수업 수식으로 토큰 서명 검증 (ES256)"},
        ],
        "categories": CATEGORIES,
    }


def get_event_or_404(event_id):
    ev = get_db().execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if ev is None:
        abort(404)
    return ev


def require_owner(row):
    if row["author_sub"] != current_user()["sub"]:
        abort(403)


def read_event_form():
    f = request.form
    form = {k: f.get(k, "").strip() for k in ("title", "date", "start_time", "end_time", "category", "location", "memo")}
    errors = []
    if not 1 <= len(form["title"]) <= 100:
        errors.append("제목은 1~100자로 입력하세요.")
    try:
        dt.date.fromisoformat(form["date"])
    except ValueError:
        errors.append("날짜를 올바르게 입력하세요.")
    for key in ("start_time", "end_time"):
        if form[key]:
            try:
                dt.time.fromisoformat(form[key])
            except ValueError:
                errors.append("시간을 올바르게 입력하세요.")
    if form["end_time"] and not form["start_time"]:
        errors.append("종료 시간을 넣으려면 시작 시간도 입력하세요.")
    if form["start_time"] and form["end_time"] and form["end_time"] < form["start_time"]:
        errors.append("종료 시간이 시작 시간보다 빠릅니다.")
    if form["category"] not in CATEGORIES:
        errors.append("분류를 선택하세요.")
    if len(form["location"]) > 100 or len(form["memo"]) > 2000:
        errors.append("장소는 100자, 메모는 2000자 이내로 입력하세요.")
    return form, errors


# ── 달력 ────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    today = dt.date.today()
    year = request.args.get("y", today.year, type=int)
    month = request.args.get("m", today.month, type=int)
    if not (1 <= month <= 12 and 1900 <= year <= 2100):
        year, month = today.year, today.month

    weeks = calendar.Calendar(firstweekday=6).monthdatescalendar(year, month)  # 일요일 시작
    first, last = weeks[0][0], weeks[-1][-1]
    rows = get_db().execute(
        "SELECT * FROM events WHERE date BETWEEN ? AND ? ORDER BY date, start_time IS NOT NULL, start_time",
        (first.isoformat(), last.isoformat()),
    ).fetchall()
    by_date = {}
    for ev in rows:
        by_date.setdefault(ev["date"], []).append(ev)

    upcoming = get_db().execute(
        "SELECT * FROM events WHERE date >= ? ORDER BY date, start_time IS NOT NULL, start_time LIMIT 6",
        (today.isoformat(),),
    ).fetchall()

    prev_m = (year - 1, 12) if month == 1 else (year, month - 1)
    next_m = (year + 1, 1) if month == 12 else (year, month + 1)
    return render_template("calendar.html", year=year, month=month, weeks=weeks, by_date=by_date,
                           today=today, weekdays=WEEKDAYS, upcoming=upcoming, prev_m=prev_m, next_m=next_m)


# ── 일정 ────────────────────────────────────────────────────────────
@app.route("/events/new", methods=["GET", "POST"])
@login_required
def new_event():
    if request.method == "POST":
        form, errors = read_event_form()
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("event_form.html", form=form, editing=False)
        user = current_user()
        cur = get_db().execute(
            """INSERT INTO events (title, date, start_time, end_time, category, location, memo,
                                   author_sub, author_name, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (form["title"], form["date"], form["start_time"] or None, form["end_time"] or None, form["category"],
             form["location"], form["memo"], user["sub"], user["display_name"], int(time.time())),
        )
        get_db().commit()
        flash("일정을 등록했습니다.")
        return redirect(url_for("event_detail", event_id=cur.lastrowid))

    date = request.args.get("date") or dt.date.today().isoformat()
    return render_template("event_form.html", form={"date": date, "category": "회의"}, editing=False)


@app.route("/events/<int:event_id>")
@login_required
def event_detail(event_id):
    return render_template("event_detail.html", ev=get_event_or_404(event_id))


@app.route("/events/<int:event_id>/edit", methods=["GET", "POST"])
@login_required
def edit_event(event_id):
    ev = get_event_or_404(event_id)
    require_owner(ev)
    if request.method == "POST":
        form, errors = read_event_form()
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("event_form.html", form=form, editing=True, ev=ev)
        get_db().execute(
            """UPDATE events SET title = ?, date = ?, start_time = ?, end_time = ?, category = ?,
                                 location = ?, memo = ? WHERE id = ?""",
            (form["title"], form["date"], form["start_time"] or None, form["end_time"] or None, form["category"],
             form["location"], form["memo"], event_id),
        )
        get_db().commit()
        flash("일정을 수정했습니다.")
        return redirect(url_for("event_detail", event_id=event_id))
    return render_template("event_form.html", form=ev, editing=True, ev=ev)


@app.post("/events/<int:event_id>/delete")
@login_required
def delete_event(event_id):
    ev = get_event_or_404(event_id)
    require_owner(ev)
    get_db().execute("DELETE FROM events WHERE id = ?", (event_id,))
    get_db().commit()
    d = dt.date.fromisoformat(ev["date"])
    flash("일정을 삭제했습니다.")
    return redirect(url_for("index", y=d.year, m=d.month))


# ── 세션 정보와 보안 도구 ───────────────────────────────────────────
@app.route("/session")
@login_required
def session_info():
    return render_template("session.html")


@app.route("/token")
@login_required
def token_page():
    user = current_user()
    id_token = user["id_token"]
    header = jwt.get_unverified_header(id_token)  # 서명은 로그인 시 이미 검증됨
    header_b64, payload_b64, signature_b64 = id_token.split(".")
    return render_template(
        "token.html",
        header=header,
        claims=user["claims"],
        time_claims={"exp", "iat", "auth_time", "nbf"},
        parts={"header": header_b64, "payload": payload_b64, "signature": signature_b64},
    )


def fetch_jwk(kid):
    """Keycloak JWKS(공개키 목록)에서 토큰의 kid와 일치하는 키를 찾는다"""
    jwks_uri = oauth.keycloak.load_server_metadata()["jwks_uri"]
    keys = requests.get(jwks_uri, timeout=5).json()["keys"]
    return next((k for k in keys if k.get("kid") == kid), None)


@app.route("/ecdsa")
@login_required
def ecdsa_page():
    id_token = current_user()["id_token"]
    header = jwt.get_unverified_header(id_token)
    if header.get("alg") != "ES256":
        return render_template("ecdsa.html", header=header, error="ES256 토큰이 아닙니다. "
                               "Keycloak 서명 알고리즘을 ES256으로 바꾼 뒤 다시 로그인하세요.")

    jwk = fetch_jwk(header["kid"])
    if jwk is None:
        return render_template("ecdsa.html", header=header, error="JWKS에서 kid에 맞는 공개키를 찾지 못했습니다.")

    # ① 수업 수식으로 직접 검증
    manual = ecdsa_manual.verify_jwt_es256(id_token, jwk)

    # ② 라이브러리(PyJWT)로 검증한 결과와 비교
    try:
        jwt.decode(id_token, jwt.PyJWK(jwk).key, algorithms=["ES256"], options={"verify_aud": False, "verify_exp": False})
        library_valid = True
    except jwt.PyJWTError:
        library_valid = False

    # ③ 변조 실험: 페이로드의 사용자 이름을 바꾸고 원래 서명으로 검증
    h, p, s = id_token.split(".")
    payload = json.loads(ecdsa_manual.b64url_decode(p))
    payload["preferred_username"] = "attacker"
    forged = ".".join([h, ecdsa_manual.b64url_encode(json.dumps(payload, separators=(",", ":")).encode()), s])
    tampered = ecdsa_manual.verify_jwt_es256(forged, jwk)

    public_jwk = {k: jwk[k] for k in ("kty", "crv", "kid", "alg", "x", "y") if k in jwk}
    return render_template("ecdsa.html", header=header, jwk=public_jwk,
                           m=manual, library_valid=library_valid, tampered=tampered,
                           curve={"p": ecdsa_manual.P, "n": ecdsa_manual.N, "Gx": ecdsa_manual.G[0], "Gy": ecdsa_manual.G[1]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ["PORT"]), debug=True)
