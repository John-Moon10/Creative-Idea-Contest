#!/usr/bin/env python3
import cgi
import errno
import hashlib
import hmac
import json
import os
import secrets
import shutil
import socket
import sqlite3
import threading
import time
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "safenet.sqlite3"
UPLOAD_DIR = ROOT / "uploads"
SESSION_COOKIE = "safenet_session"
SERVER_PORT = int(os.environ.get("PORT", "8080"))
DEFAULT_REPORT_INSTRUCTION = "가까운 직원 또는 안내 데스크에 알려주세요."
PASSWORD_ITERATIONS = 120_000

state = {
    "version": 0,
    "sessions": {},
}
state_lock = threading.Lock()


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    UPLOAD_DIR.mkdir(exist_ok=True)
    with connect_db() as conn:
        conn.execute(
            """
            create table if not exists companies (
                id text primary key,
                name text not null,
                code text not null unique,
                password_hash text not null,
                report_instruction text not null default '가까운 직원 또는 안내 데스크에 알려주세요.',
                created_at real not null
            )
            """
        )
        conn.execute(
            """
            create table if not exists alerts (
                id text primary key,
                company_id text,
                photo_url text not null default '',
                name text not null,
                gender text not null,
                age text not null,
                detail text not null,
                created_at real not null,
                foreign key (company_id) references companies(id)
            )
            """
        )
        columns = {row["name"] for row in conn.execute("pragma table_info(alerts)").fetchall()}
        if "company_id" not in columns:
            conn.execute("alter table alerts add column company_id text")
        company_columns = {row["name"] for row in conn.execute("pragma table_info(companies)").fetchall()}
        if "report_instruction" not in company_columns:
            conn.execute(
                f"alter table companies add column report_instruction text not null default '{DEFAULT_REPORT_INSTRUCTION}'"
            )
        conn.execute(
            """
            delete from alerts
            where rowid not in (
                select max(rowid)
                from alerts
                where company_id is not null
                group by company_id, name, gender, age, detail
            )
            and company_id is not null
            """
        )
        conn.execute(
            """
            create unique index if not exists unique_company_alert_content
            on alerts (company_id, name, gender, age, detail)
            """
        )
        conn.commit()


def normalize_code(value):
    code = "".join(ch for ch in value.strip().lower() if ch.isalnum() or ch in ["-", "_"])
    return code[:40]


def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PASSWORD_ITERATIONS)
    return f"{salt}:{digest.hex()}"


def verify_password(password, stored):
    try:
        salt, digest = stored.split(":", 1)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PASSWORD_ITERATIONS).hex()
    return hmac.compare_digest(actual, digest)


def make_id():
    return secrets.token_urlsafe(12)


def public_company(company, base_url=None):
    if not company:
        return None
    display_path = f"/child-alert-mobile.html?company={company['code']}"
    if base_url:
        wifi_portal_url = f"{base_url.rstrip('/')}{display_path}"
    else:
        wifi_portal_url = f"http://{local_ip()}:{SERVER_PORT}{display_path}"
    return {
        "id": company["id"],
        "name": company["name"],
        "code": company["code"],
        "reportInstruction": company["report_instruction"],
        "displayUrl": display_path,
        "wifiPortalUrl": wifi_portal_url,
    }


def get_company_by_code(code):
    with connect_db() as conn:
        return conn.execute("select * from companies where code = ?", (code,)).fetchone()


def get_company_by_id(company_id):
    with connect_db() as conn:
        return conn.execute("select * from companies where id = ?", (company_id,)).fetchone()


def db_rows(company_id):
    with connect_db() as conn:
        rows = conn.execute(
            """
            select id, photo_url, name, gender, age, detail, created_at
            from alerts
            where company_id = ?
            order by created_at desc
            """,
            (company_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def bump_version():
    with state_lock:
        state["version"] += 1
        return state["version"]


def current_version():
    with state_lock:
        return state["version"]


def make_session(company_id):
    token = secrets.token_urlsafe(32)
    with state_lock:
        state["sessions"][token] = company_id
    return token


def session_company_id(token):
    with state_lock:
        return state["sessions"].get(token)


def remove_session(token):
    with state_lock:
        state["sessions"].pop(token, None)


def local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


class Handler(SimpleHTTPRequestHandler):
    server_version = "SafeNet/2.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def base_url(self):
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or f"127.0.0.1:{SERVER_PORT}"
        proto = (self.headers.get("X-Forwarded-Proto") or "").split(",", 1)[0].strip()
        if not proto:
            proto = "http" if host.startswith(("127.0.0.1", "localhost")) else "https"
        return f"{proto}://{host}"

    def public_company(self, company):
        return public_company(company, self.base_url())

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/":
            self.redirect("/child-alert-admin.html")
            return
        if path == "/admin":
            self.redirect("/child-alert-admin.html")
            return
        if path == "/display":
            company = query.get("company", [""])[0]
            target = "/child-alert-mobile.html"
            if company:
                target += f"?company={normalize_code(company)}"
            self.redirect(target)
            return
        if path == "/healthz":
            self.send_json({"ok": True, "service": "SafeNet"})
            return
        if path == "/api/session":
            company = self.current_company()
            self.send_json({"loggedIn": bool(company), "company": self.public_company(company)})
            return
        if path == "/api/alerts":
            company = self.current_company()
            if not company:
                self.send_json({"error": "기업 로그인이 필요합니다."}, HTTPStatus.UNAUTHORIZED)
                return
            self.send_json({"alerts": db_rows(company["id"]), "version": current_version(), "company": self.public_company(company)})
            return
        if path == "/api/public/alerts":
            code = normalize_code(query.get("company", [""])[0])
            company = get_company_by_code(code)
            if not company:
                self.send_json({"error": "기업을 찾을 수 없습니다."}, HTTPStatus.NOT_FOUND)
                return
            self.send_json({"alerts": db_rows(company["id"]), "version": current_version(), "company": self.public_company(company)})
            return
        if path == "/api/events":
            self.handle_events()
            return
        super().do_GET()

    def do_HEAD(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/":
            self.head_redirect("/child-alert-admin.html")
            return
        if path == "/admin":
            self.head_redirect("/child-alert-admin.html")
            return
        if path == "/display":
            company = query.get("company", [""])[0]
            target = "/child-alert-mobile.html"
            if company:
                target += f"?company={normalize_code(company)}"
            self.head_redirect(target)
            return
        super().do_HEAD()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/signup":
            self.handle_signup()
            return
        if path == "/api/login":
            self.handle_login()
            return
        if path == "/api/logout":
            self.handle_logout()
            return
        if path == "/api/company":
            company = self.current_company()
            if not company:
                self.send_json({"error": "기업 로그인이 필요합니다."}, HTTPStatus.UNAUTHORIZED)
                return
            self.handle_update_company(company)
            return
        if path == "/api/alerts":
            company = self.current_company()
            if not company:
                self.send_json({"error": "기업 로그인이 필요합니다."}, HTTPStatus.UNAUTHORIZED)
                return
            self.handle_create_alert(company)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_DELETE(self):
        path = urlparse(self.path).path
        company = self.current_company()
        if not company:
            self.send_json({"error": "기업 로그인이 필요합니다."}, HTTPStatus.UNAUTHORIZED)
            return
        if path == "/api/alerts":
            self.delete_all_alerts(company["id"])
            return
        if path.startswith("/api/alerts/"):
            alert_id = path.rsplit("/", 1)[-1]
            self.delete_alert(company["id"], alert_id)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def redirect(self, location):
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.end_headers()

    def head_redirect(self, location):
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.end_headers()

    def send_json(self, payload, status=HTTPStatus.OK, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        return json.loads(raw or "{}")

    def cookie_value(self, name):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if "=" not in part:
                continue
            key, value = part.strip().split("=", 1)
            if key == name:
                return value
        return ""

    def current_company(self):
        company_id = session_company_id(self.cookie_value(SESSION_COOKIE))
        return get_company_by_id(company_id) if company_id else None

    def handle_signup(self):
        try:
            payload = self.read_json()
        except json.JSONDecodeError:
            self.send_json({"error": "잘못된 요청입니다."}, HTTPStatus.BAD_REQUEST)
            return

        name = str(payload.get("companyName", "")).strip()
        code = normalize_code(str(payload.get("companyCode", "")))
        password = str(payload.get("password", ""))
        if not name or not code or len(password) < 4:
            self.send_json({"error": "기업명, 기업 코드, 4자리 이상 비밀번호가 필요합니다."}, HTTPStatus.BAD_REQUEST)
            return

        company_id = make_id()
        try:
            with connect_db() as conn:
                conn.execute(
                    """
                    insert into companies (id, name, code, password_hash, report_instruction, created_at)
                    values (?, ?, ?, ?, ?, ?)
                    """,
                    (company_id, name, code, hash_password(password), DEFAULT_REPORT_INSTRUCTION, time.time()),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            self.send_json({"error": "이미 사용 중인 기업 코드입니다."}, HTTPStatus.CONFLICT)
            return

        token = make_session(company_id)
        self.send_json(
            {"ok": True, "company": self.public_company(get_company_by_id(company_id))},
            extra_headers={"Set-Cookie": f"{SESSION_COOKIE}={token}; Path=/; SameSite=Lax; HttpOnly"},
        )

    def handle_login(self):
        try:
            payload = self.read_json()
        except json.JSONDecodeError:
            self.send_json({"error": "잘못된 요청입니다."}, HTTPStatus.BAD_REQUEST)
            return

        code = normalize_code(str(payload.get("companyCode", "")))
        password = str(payload.get("password", ""))
        company = get_company_by_code(code)
        if not company or not verify_password(password, company["password_hash"]):
            self.send_json({"error": "기업 코드 또는 비밀번호가 맞지 않습니다."}, HTTPStatus.UNAUTHORIZED)
            return

        token = make_session(company["id"])
        self.send_json(
            {"ok": True, "company": self.public_company(company)},
            extra_headers={"Set-Cookie": f"{SESSION_COOKIE}={token}; Path=/; SameSite=Lax; HttpOnly"},
        )

    def handle_update_company(self, company):
        try:
            payload = self.read_json()
        except json.JSONDecodeError:
            self.send_json({"error": "잘못된 요청입니다."}, HTTPStatus.BAD_REQUEST)
            return

        report_instruction = str(payload.get("reportInstruction", "")).strip()
        if not report_instruction:
            self.send_json({"error": "신고 안내 문구를 입력해주세요."}, HTTPStatus.BAD_REQUEST)
            return
        if len(report_instruction) > 160:
            self.send_json({"error": "신고 안내 문구는 160자 이하로 입력해주세요."}, HTTPStatus.BAD_REQUEST)
            return

        with connect_db() as conn:
            conn.execute(
                "update companies set report_instruction = ? where id = ?",
                (report_instruction, company["id"]),
            )
            conn.commit()
        bump_version()
        self.send_json({"ok": True, "company": self.public_company(get_company_by_id(company["id"]))})

    def handle_logout(self):
        remove_session(self.cookie_value(SESSION_COOKIE))
        self.send_json(
            {"ok": True},
            extra_headers={"Set-Cookie": f"{SESSION_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly"},
        )

    def handle_create_alert(self, company):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": self.headers.get("Content-Type"),
            },
        )
        name = (form.getfirst("name") or "").strip()
        gender = (form.getfirst("gender") or "").strip()
        age = (form.getfirst("age") or "").strip()
        detail = (form.getfirst("detail") or "").strip()
        if not name or not gender or not age or not detail:
            self.send_json({"error": "필수 정보를 모두 입력해주세요."}, HTTPStatus.BAD_REQUEST)
            return
        if gender not in {"남자", "여자"}:
            self.send_json({"error": "성별은 남자 또는 여자만 선택할 수 있습니다."}, HTTPStatus.BAD_REQUEST)
            return
        try:
            age_number = int(age)
        except ValueError:
            self.send_json({"error": "나이는 숫자로 입력해주세요."}, HTTPStatus.BAD_REQUEST)
            return
        if age_number < 0 or age_number > 120:
            self.send_json({"error": "나이는 0세 이상 120세 이하로 입력해주세요."}, HTTPStatus.BAD_REQUEST)
            return

        alert_id = make_id()
        photo_url = ""
        photo = form["photo"] if "photo" in form else None
        if photo is not None and getattr(photo, "filename", ""):
            filename = Path(photo.filename).name
            suffix = Path(filename).suffix.lower()
            if suffix not in [".jpg", ".jpeg", ".png", ".gif", ".webp"]:
                self.send_json({"error": "사진 파일 형식은 jpg, png, gif, webp만 가능합니다."}, HTTPStatus.BAD_REQUEST)
                return
            digest = hashlib.sha256(f"{company['id']}:{alert_id}:{filename}".encode("utf-8")).hexdigest()[:16]
            saved_name = f"{company['code']}-{digest}{suffix}"
            saved_path = UPLOAD_DIR / saved_name
            with saved_path.open("wb") as output:
                shutil.copyfileobj(photo.file, output)
            photo_url = f"/uploads/{saved_name}"

        try:
            with connect_db() as conn:
                conn.execute(
                    """
                    insert into alerts (id, company_id, photo_url, name, gender, age, detail, created_at)
                    values (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (alert_id, company["id"], photo_url, name, gender, age, detail, time.time()),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            self.remove_photo(photo_url)
            self.send_json({"error": "이미 같은 내용의 알림이 등록되어 있습니다."}, HTTPStatus.CONFLICT)
            return
        bump_version()
        self.send_json({"ok": True, "id": alert_id})

    def delete_alert(self, company_id, alert_id):
        photo_url = ""
        with connect_db() as conn:
            row = conn.execute(
                "select photo_url from alerts where id = ? and company_id = ?",
                (alert_id, company_id),
            ).fetchone()
            if row:
                photo_url = row["photo_url"]
            conn.execute("delete from alerts where id = ? and company_id = ?", (alert_id, company_id))
            conn.commit()
        self.remove_photo(photo_url)
        bump_version()
        self.send_json({"ok": True})

    def delete_all_alerts(self, company_id):
        rows = db_rows(company_id)
        with connect_db() as conn:
            conn.execute("delete from alerts where company_id = ?", (company_id,))
            conn.commit()
        for row in rows:
            self.remove_photo(row.get("photo_url", ""))
        bump_version()
        self.send_json({"ok": True})

    def remove_photo(self, photo_url):
        if not photo_url.startswith("/uploads/"):
            return
        path = ROOT / photo_url.lstrip("/")
        try:
            if path.is_file():
                path.unlink()
        except OSError:
            pass

    def handle_events(self):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        last_seen = -1
        try:
            for _ in range(3600):
                version = current_version()
                if version != last_seen:
                    last_seen = version
                    payload = json.dumps({"version": version}, ensure_ascii=False)
                    self.wfile.write(f"event: alerts\ndata: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                time.sleep(1)
        except (BrokenPipeError, ConnectionResetError):
            return


def main():
    init_db()
    try:
        server = ThreadingHTTPServer(("0.0.0.0", SERVER_PORT), Handler)
    except OSError as error:
        if error.errno == errno.EADDRINUSE:
            print(f"이미 서버가 실행 중이거나 {SERVER_PORT}번 포트를 다른 프로그램이 사용 중입니다.")
            print(f"브라우저에서 http://127.0.0.1:{SERVER_PORT}/admin 으로 접속해보세요.")
            print("새로 다시 켜고 싶으면 기존 서버를 끈 뒤 다시 실행하세요.")
            print("다른 포트로 실행하려면 예: PORT=8081 python3 server.py")
            return
        raise
    print(f"SafeNet 서버 실행 중: http://127.0.0.1:{SERVER_PORT}")
    print(f"같은 와이파이의 다른 기기에서는 http://{local_ip()}:{SERVER_PORT}/admin 으로 접속하세요.")
    print("기업 회원가입/로그인 방식으로 실행됩니다.")
    server.serve_forever()


if __name__ == "__main__":
    main()
