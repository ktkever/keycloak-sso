"""서비스 A: 팀 게시판 (포트 3001)

- 카테고리(공지/자유/질문/자료)별 게시글, 검색, 페이지 나누기
- 댓글
- 작성자 본인만 글·댓글 수정/삭제 (작성자 = Keycloak 토큰의 sub)
- 데이터는 SQLite(data.db)에 저장
"""
import math
import os
import sqlite3
import time
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).parent
load_dotenv(BASE_DIR / ".env")

from flask import Flask, abort, flash, g, redirect, render_template, request, url_for  # noqa: E402

from auth import current_user, init_auth, login_required  # noqa: E402

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
# A와 B가 같은 localhost라 쿠키가 공유되므로, 쿠키 이름을 서비스마다 다르게 지정
app.config["SESSION_COOKIE_NAME"] = "session_service_a"
init_auth(app)

DB_PATH = os.environ.get("DB_PATH", str(BASE_DIR / "data.db"))
CATEGORIES = ["공지", "자유", "질문", "자료"]
PER_PAGE = 15

SCHEMA = """
CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    author_sub TEXT NOT NULL,
    author_name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER,
    views INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    author_sub TEXT NOT NULL,
    author_name TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
"""


# ── DB ──────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
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


@app.context_processor
def inject_common():
    return {
        "user": current_user(),
        "other_service": {"name": "PlanIt 일정", "url": os.environ["OTHER_SERVICE_URL"]},
        "security_links": [],
    }


def get_post_or_404(post_id):
    post = get_db().execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if post is None:
        abort(404)
    return post


def require_owner(row):
    if row["author_sub"] != current_user()["sub"]:
        abort(403)


def read_post_form():
    category = request.form.get("category", "")
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    errors = []
    if category not in CATEGORIES:
        errors.append("카테고리를 선택하세요.")
    if not 1 <= len(title) <= 100:
        errors.append("제목은 1~100자로 입력하세요.")
    if not 1 <= len(body) <= 5000:
        errors.append("내용은 1~5000자로 입력하세요.")
    return {"category": category, "title": title, "body": body}, errors


# ── 게시글 ──────────────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    cat = request.args.get("cat", "")
    q = request.args.get("q", "").strip()
    page = max(request.args.get("page", 1, type=int), 1)

    where, params = [], []
    if cat in CATEGORIES:
        where.append("p.category = ?")
        params.append(cat)
    if q:
        where.append("(p.title LIKE ? OR p.body LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    db = get_db()
    total = db.execute(f"SELECT COUNT(*) FROM posts p {where_sql}", params).fetchone()[0]
    pages = max(math.ceil(total / PER_PAGE), 1)
    page = min(page, pages)
    posts = db.execute(
        f"""SELECT p.*, (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
            FROM posts p {where_sql}
            ORDER BY (p.category = '공지') DESC, p.created_at DESC, p.id DESC
            LIMIT ? OFFSET ?""",
        params + [PER_PAGE, (page - 1) * PER_PAGE],
    ).fetchall()
    return render_template("board_list.html", posts=posts, categories=CATEGORIES,
                           cat=cat, q=q, page=page, pages=pages, total=total)


@app.route("/posts/new", methods=["GET", "POST"])
@login_required
def new_post():
    if request.method == "POST":
        form, errors = read_post_form()
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("board_form.html", form=form, categories=CATEGORIES, editing=False)
        user = current_user()
        cur = get_db().execute(
            "INSERT INTO posts (category, title, body, author_sub, author_name, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (form["category"], form["title"], form["body"], user["sub"], user["display_name"], int(time.time())),
        )
        get_db().commit()
        flash("글을 등록했습니다.")
        return redirect(url_for("post_detail", post_id=cur.lastrowid))
    return render_template("board_form.html", form={"category": "자유"}, categories=CATEGORIES, editing=False)


@app.route("/posts/<int:post_id>")
@login_required
def post_detail(post_id):
    db = get_db()
    get_post_or_404(post_id)
    db.execute("UPDATE posts SET views = views + 1 WHERE id = ?", (post_id,))
    db.commit()
    post = get_post_or_404(post_id)
    comments = db.execute("SELECT * FROM comments WHERE post_id = ? ORDER BY created_at, id", (post_id,)).fetchall()
    return render_template("board_detail.html", post=post, comments=comments)


@app.route("/posts/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    post = get_post_or_404(post_id)
    require_owner(post)
    if request.method == "POST":
        form, errors = read_post_form()
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("board_form.html", form=form, categories=CATEGORIES, editing=True, post=post)
        get_db().execute(
            "UPDATE posts SET category = ?, title = ?, body = ?, updated_at = ? WHERE id = ?",
            (form["category"], form["title"], form["body"], int(time.time()), post_id),
        )
        get_db().commit()
        flash("글을 수정했습니다.")
        return redirect(url_for("post_detail", post_id=post_id))
    return render_template("board_form.html", form=post, categories=CATEGORIES, editing=True, post=post)


@app.post("/posts/<int:post_id>/delete")
@login_required
def delete_post(post_id):
    require_owner(get_post_or_404(post_id))
    get_db().execute("DELETE FROM posts WHERE id = ?", (post_id,))
    get_db().commit()
    flash("글을 삭제했습니다.")
    return redirect(url_for("index"))


# ── 댓글 ────────────────────────────────────────────────────────────
@app.post("/posts/<int:post_id>/comments")
@login_required
def add_comment(post_id):
    get_post_or_404(post_id)
    body = request.form.get("body", "").strip()
    if not 1 <= len(body) <= 1000:
        flash("댓글은 1~1000자로 입력하세요.", "error")
    else:
        user = current_user()
        get_db().execute(
            "INSERT INTO comments (post_id, body, author_sub, author_name, created_at) VALUES (?, ?, ?, ?, ?)",
            (post_id, body, user["sub"], user["display_name"], int(time.time())),
        )
        get_db().commit()
    return redirect(url_for("post_detail", post_id=post_id) + "#comments")


@app.post("/comments/<int:comment_id>/delete")
@login_required
def delete_comment(comment_id):
    comment = get_db().execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()
    if comment is None:
        abort(404)
    require_owner(comment)
    get_db().execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    get_db().commit()
    return redirect(url_for("post_detail", post_id=comment["post_id"]) + "#comments")


# ── 세션 정보 ───────────────────────────────────────────────────────
@app.route("/session")
@login_required
def session_info():
    return render_template("session.html")


if __name__ == "__main__":
    # 0.0.0.0: Docker 안의 Keycloak이 백채널 로그아웃을 보낼 수 있도록 외부 연결 허용
    app.run(host="0.0.0.0", port=int(os.environ["PORT"]), debug=True)
