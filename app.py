"""Women's Safety Incident Heatmap - Flask application.

Features: registration/login with roles (admin / officer / citizen), incident reporting,
area-wise and time-wise analysis, heatmap data API, hotspot risk scoring,
summary report + CSV export, and admin user management.
"""
import csv
import io
import math
import os
import re
import secrets
import sqlite3
import zipfile
from datetime import date, datetime, timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "safety.db"))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-in-production")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
STATUSES = ["Reported", "Under Review", "Resolved", "Rejected"]
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15

SLOT_SQL = """CASE
    WHEN i.hour_of_day >= 22 OR i.hour_of_day < 5 THEN 'Night (10PM-5AM)'
    WHEN i.hour_of_day < 12 THEN 'Morning (5AM-12PM)'
    WHEN i.hour_of_day < 17 THEN 'Afternoon (12PM-5PM)'
    ELSE 'Evening (5PM-10PM)' END"""
SLOTS = ["Morning (5AM-12PM)", "Afternoon (12PM-5PM)", "Evening (5PM-10PM)", "Night (10PM-5AM)"]


# --------------------------------------------------------------------------- database
INQUIRIES_DDL = """CREATE TABLE IF NOT EXISTS inquiries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    category    TEXT NOT NULL,
    subject     TEXT NOT NULL,
    message     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Answered', 'Closed')),
    reply       TEXT,
    replied_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    replied_at  TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
)"""
TRIPS_DDL = """CREATE TABLE IF NOT EXISTS trips (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    from_area_id  INTEGER NOT NULL REFERENCES areas(id),
    to_area_id    INTEGER NOT NULL REFERENCES areas(id),
    contact_name  TEXT NOT NULL,
    contact_phone TEXT NOT NULL,
    note          TEXT,
    token         TEXT NOT NULL UNIQUE,
    started_at    TEXT NOT NULL,
    deadline      TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Safe', 'SOS', 'Cancelled')),
    ended_at      TEXT,
    extended_count INTEGER NOT NULL DEFAULT 0
)"""
_schema_checked = set()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        # Older safety.db files (created before the inquiry module) get the new table automatically.
        if DB_PATH not in _schema_checked:
            g.db.execute(INQUIRIES_DDL)
            g.db.execute(TRIPS_DDL)
            g.db.commit()
            _schema_checked.add(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, params=(), one=False):
    cur = get_db().execute(sql, params)
    rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(sql, params=()):
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    return cur


# --------------------------------------------------------------------------- auth helpers
@app.before_request
def load_user_and_csrf():
    g.user = None
    uid = session.get("user_id")
    if uid:
        g.user = query("SELECT * FROM users WHERE id = ? AND is_active = 1", (uid,), one=True)
        if g.user is None:
            session.clear()
    if request.method == "POST":
        token = session.get("csrf_token")
        if not token or token != request.form.get("csrf_token"):
            abort(400, "Invalid or missing CSRF token. Please go back and refresh the page.")


@app.context_processor
def inject_globals():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return {"csrf_token": session["csrf_token"], "current_user": g.get("user"), "DAYS": DAYS}


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if g.user is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*a, **kw)
    return wrapper


def roles_required(*roles):
    def deco(f):
        @wraps(f)
        @login_required
        def wrapper(*a, **kw):
            if g.user["role"] not in roles:
                abort(403)
            return f(*a, **kw)
        return wrapper
    return deco


def is_locked_out(email):
    row = query(
        """SELECT COUNT(*) c FROM login_log
           WHERE email = ? AND success = 0 AND created_at >= datetime('now', ?)""",
        (email, f"-{LOCKOUT_MINUTES} minutes"), one=True)
    return row["c"] >= MAX_FAILED_LOGINS


@app.route("/")
def index():
    return redirect(url_for("dashboard" if g.user else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pwd = request.form.get("password", "")
        errors = []
        if len(name) < 2:
            errors.append("Name must be at least 2 characters.")
        if "@" not in email or "." not in email:
            errors.append("Enter a valid email address.")
        if len(pwd) < 8 or pwd.isalpha() or pwd.isdigit():
            errors.append("Password needs 8+ characters with letters and numbers.")
        if pwd != request.form.get("confirm", ""):
            errors.append("Passwords do not match.")
        if not errors and query("SELECT 1 FROM users WHERE email = ?", (email,), one=True):
            errors.append("An account with this email already exists.")
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", name=name, email=email), 400
        execute("INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?,'citizen')",
                (name, email, generate_password_hash(pwd)))
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", name="", email="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pwd = request.form.get("password", "")
        if is_locked_out(email):
            flash(f"Too many failed attempts. Try again after {LOCKOUT_MINUTES} minutes.", "danger")
            return render_template("login.html"), 429
        user = query("SELECT * FROM users WHERE email = ? AND is_active = 1", (email,), one=True)
        ok = bool(user and check_password_hash(user["password_hash"], pwd))
        execute("INSERT INTO login_log (email, success, ip) VALUES (?,?,?)",
                (email, int(ok), request.remote_addr))
        if not ok:
            flash("Invalid email or password.", "danger")
            return render_template("login.html"), 401
        session.clear()
        session["user_id"] = user["id"]
        session["csrf_token"] = secrets.token_hex(16)
        flash(f"Welcome back, {user['name']}!", "success")
        nxt = request.args.get("next", "")
        return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------- filters
def build_filters(args):
    """WHERE clause for incidents aliased as i, from query-string filters."""
    where, params = ["1=1"], []
    if args.get("area_id", "").isdigit():
        where.append("i.area_id = ?"); params.append(int(args["area_id"]))
    if args.get("type_id", "").isdigit():
        where.append("i.type_id = ?"); params.append(int(args["type_id"]))
    if args.get("status") in STATUSES:
        where.append("i.status = ?"); params.append(args["status"])
    if args.get("slot") in SLOTS:
        where.append(f"({SLOT_SQL}) = ?"); params.append(args["slot"])
    if args.get("weekday", "").isdigit() and int(args["weekday"]) <= 6:      # 0 = Monday
        where.append("i.day_of_week = ?"); params.append(int(args["weekday"]))
    if args.get("hour", "").isdigit() and int(args["hour"]) <= 23:
        where.append("i.hour_of_day = ?"); params.append(int(args["hour"]))
    for key, op in (("date_from", ">="), ("date_to", "<=")):
        val = args.get(key, "")
        try:
            datetime.strptime(val, "%Y-%m-%d")
        except ValueError:
            continue
        where.append(f"date(i.incident_time) {op} ?"); params.append(val)
    return " AND ".join(where), params


def lookups():
    return (query("SELECT * FROM areas ORDER BY name"),
            query("SELECT * FROM incident_types ORDER BY name"))


# --------------------------------------------------------------------------- dashboard + APIs
@app.route("/dashboard")
@login_required
def dashboard():
    areas, types = lookups()
    return render_template("dashboard.html", areas=areas, types=types, statuses=STATUSES,
                           slots=SLOTS, f=request.args)


@app.route("/api/heatmap")
@login_required
def api_heatmap():
    where, params = build_filters(request.args)
    rows = query(f"""SELECT i.latitude, i.longitude, t.severity
                     FROM incidents i JOIN incident_types t ON t.id = i.type_id WHERE {where}""", params)
    return jsonify([[r["latitude"], r["longitude"], r["severity"] / 5.0] for r in rows])


def risk_level(score, max_score):
    if max_score == 0:
        return "Low"
    ratio = score / max_score
    return "High" if ratio >= 0.66 else "Medium" if ratio >= 0.33 else "Low"


def compute_stats(args):
    where, params = build_filters(args)
    base = "FROM incidents i JOIN areas a ON a.id=i.area_id JOIN incident_types t ON t.id=i.type_id"

    k = query(f"""SELECT COUNT(*) total, COALESCE(SUM(i.status='Resolved'),0) resolved,
                  COALESCE(SUM(i.status IN ('Reported','Under Review')),0) open_cases,
                  COALESCE(SUM(t.severity>=4),0) severe {base} WHERE {where}""", params, one=True)
    total = k["total"]

    by_area = [dict(r) for r in query(f"""
        SELECT a.id, a.name, a.lat, a.lng, COUNT(i.id) incidents, SUM(t.severity) risk_score,
               ROUND(100.0*SUM(i.status='Resolved')/COUNT(i.id),1) resolved_pct
        {base} WHERE {where} GROUP BY a.id ORDER BY risk_score DESC""", params)]
    max_risk = by_area[0]["risk_score"] if by_area else 0
    for r in by_area:
        r["level"] = risk_level(r["risk_score"], max_risk)

    hours = {r["h"]: r["c"] for r in query(
        f"SELECT i.hour_of_day h, COUNT(*) c {base} WHERE {where} GROUP BY h", params)}
    wk = {r["d"]: r["c"] for r in query(
        f"SELECT i.day_of_week d, COUNT(*) c {base} WHERE {where} GROUP BY d", params)}
    slot = {r["s"]: r["c"] for r in query(
        f"SELECT {SLOT_SQL} s, COUNT(*) c {base} WHERE {where} GROUP BY s", params)}

    matrix = {}
    for r in query(f"SELECT a.name an, {SLOT_SQL} s, COUNT(*) c {base} WHERE {where} GROUP BY a.id, s", params):
        matrix.setdefault(r["an"], {})[r["s"]] = r["c"]

    by_type = [dict(r) for r in query(f"""
        SELECT t.id, t.name, t.severity, COUNT(i.id) incidents {base} WHERE {where}
        GROUP BY t.id ORDER BY incidents DESC""", params)]
    trend = [dict(r) for r in query(f"""
        SELECT substr(i.incident_time,1,7) month, COUNT(*) incidents {base} WHERE {where}
        GROUP BY month ORDER BY month""", params)]

    peak_hour = max(hours, key=hours.get) if hours else None
    return {
        "kpis": {"total": total, "resolved": k["resolved"], "open": k["open_cases"], "severe": k["severe"],
                 "resolution_rate": round(100 * k["resolved"] / total, 1) if total else 0,
                 "peak_hour": peak_hour,
                 "top_area": by_area[0]["name"] if by_area else None},
        "by_area": by_area,
        "by_hour": [hours.get(h, 0) for h in range(24)],
        "by_weekday": [wk.get(d, 0) for d in range(7)],
        "by_slot": [slot.get(s, 0) for s in SLOTS],
        "slots": SLOTS,
        "matrix": [{"area": a["name"], "counts": [matrix.get(a["name"], {}).get(s, 0) for s in SLOTS]}
                   for a in by_area],
        "by_type": by_type,
        "trend": trend,
    }


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(compute_stats(request.args))


# --------------------------------------------------------------------------- incidents
@app.route("/report", methods=["GET", "POST"])
@login_required
def report_incident():
    areas, types = lookups()
    if request.method == "POST":
        f = request.form
        errors = []
        area = query("SELECT * FROM areas WHERE id = ?", (f.get("area_id", 0),), one=True)
        itype = query("SELECT * FROM incident_types WHERE id = ?", (f.get("type_id", 0),), one=True)
        if not area: errors.append("Select a valid area.")
        if not itype: errors.append("Select a valid incident type.")
        try:
            when = datetime.strptime(f.get("incident_time", ""), "%Y-%m-%dT%H:%M")
            if when > datetime.now():
                errors.append("Incident time cannot be in the future.")
        except ValueError:
            errors.append("Enter a valid date and time.")
            when = None
        desc = f.get("description", "").strip()[:1000]
        lat = lng = None
        try:
            if f.get("latitude") and f.get("longitude"):
                lat, lng = float(f["latitude"]), float(f["longitude"])
                if not (-90 <= lat <= 90 and -180 <= lng <= 180):
                    raise ValueError
        except ValueError:
            errors.append("Invalid map location.")
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("report.html", areas=areas, types=types, f=f), 400
        if lat is None:
            lat, lng = area["lat"], area["lng"]
        cur = execute(
            """INSERT INTO incidents (user_id, area_id, type_id, description, latitude, longitude,
                                      incident_time, hour_of_day, day_of_week, is_anonymous)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (g.user["id"], area["id"], itype["id"], desc, lat, lng, when.strftime("%Y-%m-%d %H:%M"),
             when.hour, when.weekday(), 1 if f.get("is_anonymous") else 0))
        flash(f"Incident #{cur.lastrowid} reported. Thank you for helping keep the community safe.", "success")
        return redirect(url_for("incidents"))
    return render_template("report.html", areas=areas, types=types, f={},
                           now=datetime.now().strftime("%Y-%m-%dT%H:%M"))


@app.route("/incidents")
@login_required
def incidents():
    where, params = build_filters(request.args)
    if g.user["role"] == "citizen":
        where += " AND i.user_id = ?"; params.append(g.user["id"])
    page = max(int(request.args.get("page", 1)) if request.args.get("page", "1").isdigit() else 1, 1)
    per = 15
    total = query(f"SELECT COUNT(*) c FROM incidents i WHERE {where}", params, one=True)["c"]
    rows = query(f"""SELECT i.*, a.name area, t.name type, t.severity, u.name reporter
                     FROM incidents i JOIN areas a ON a.id=i.area_id JOIN incident_types t ON t.id=i.type_id
                     LEFT JOIN users u ON u.id=i.user_id WHERE {where}
                     ORDER BY i.incident_time DESC LIMIT ? OFFSET ?""", params + [per, (page - 1) * per])
    areas, types = lookups()
    args = {k: v for k, v in request.args.items() if k != "page"}
    return render_template("incidents.html", rows=rows, total=total, page=page, pages=max((total + per - 1) // per, 1),
                           areas=areas, types=types, statuses=STATUSES, slots=SLOTS, f=request.args, args=args)


@app.route("/incidents/<int:incident_id>/status", methods=["POST"])
@roles_required("admin", "officer")
def update_status(incident_id):
    status = request.form.get("status")
    if status not in STATUSES:
        abort(400)
    if not query("SELECT 1 FROM incidents WHERE id = ?", (incident_id,), one=True):
        abort(404)
    execute("UPDATE incidents SET status = ? WHERE id = ?", (status, incident_id))
    flash(f"Incident #{incident_id} marked as {status}.", "success")
    return redirect(request.referrer or url_for("incidents"))


# --------------------------------------------------------------------------- reports
@app.route("/reports")
@roles_required("admin", "officer")
def reports():
    s = compute_stats(request.args)
    areas, types = lookups()
    peak = s["kpis"]["peak_hour"]
    insights = []
    if s["by_area"]:
        top3 = ", ".join(a["name"] for a in s["by_area"][:3])
        insights.append(f"Highest-risk areas: {top3}.")
    if peak is not None:
        insights.append(f"Incidents peak around {peak:02d}:00-{(peak + 1) % 24:02d}:00.")
    if sum(s["by_slot"]):
        i = s["by_slot"].index(max(s["by_slot"]))
        insights.append(f"{SLOTS[i]} is the riskiest time slot ({round(100 * s['by_slot'][i] / sum(s['by_slot']))}% of incidents).")
    if s["by_type"]:
        insights.append(f"Most common incident type: {s['by_type'][0]['name']}.")
    insights.append(f"Resolution rate is {s['kpis']['resolution_rate']}%; {s['kpis']['open']} cases are still open.")
    return render_template("reports.html", s=s, insights=insights, areas=areas, types=types,
                           statuses=STATUSES, slots=SLOTS, f=request.args, generated=datetime.now(),
                           days=DAYS, an=compute_analysis(request.args), inq=inquiry_counts())


@app.route("/reports/export.csv")
@roles_required("admin", "officer")
def export_csv():
    where, params = build_filters(request.args)
    rows = query(f"""SELECT i.id, i.incident_time, a.name area, t.name type, t.severity, i.status,
                            i.latitude, i.longitude, i.description
                     FROM incidents i JOIN areas a ON a.id=i.area_id JOIN incident_types t ON t.id=i.type_id
                     WHERE {where} ORDER BY i.incident_time DESC""", params)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ID", "Incident Time", "Area", "Type", "Severity", "Status", "Latitude", "Longitude", "Description"])
    for r in rows:
        w.writerow([r["id"], r["incident_time"], r["area"], r["type"], r["severity"], r["status"],
                    r["latitude"], r["longitude"], (r["description"] or "").replace("\n", " ")])
    fname = f"incident_report_{datetime.now():%Y%m%d_%H%M}.csv"
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


# --------------------------------------------------------------------------- admin
@app.route("/admin/users")
@roles_required("admin")
def admin_users():
    users = query("""SELECT u.*, (SELECT COUNT(*) FROM incidents WHERE user_id = u.id) reports,
                            (SELECT MAX(created_at) FROM login_log WHERE email = u.email AND success = 1) last_login
                     FROM users u ORDER BY u.id""")
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>", methods=["POST"])
@roles_required("admin")
def admin_update_user(user_id):
    if user_id == g.user["id"]:
        flash("You cannot change your own role or status.", "warning")
        return redirect(url_for("admin_users"))
    role = request.form.get("role")
    if role not in ("admin", "officer", "citizen"):
        abort(400)
    execute("UPDATE users SET role = ?, is_active = ? WHERE id = ?",
            (role, 1 if request.form.get("is_active") else 0, user_id))
    flash("User updated.", "success")
    return redirect(url_for("admin_users"))


# --------------------------------------------------------------------------- analysis
def pct(n, d):
    return round(100 * n / d) if d else 0


def compute_analysis(args):
    """Explains WHAT is happening, WHERE, WHEN, HOW (patterns), the TREND, possible WHY and ACTIONS."""
    s = compute_stats(args)
    total = s["kpis"]["total"]
    empty = {"total": 0, "findings": [], "peak_by_area": [], "trend": [], "type_by_slot": [],
             "sev_by_slot": [], "area_hour": {"areas": [], "grid": [], "max": 0},
             "type_slot": {"types": [], "slots": SLOTS, "data": []}, "stats": s}
    if not total:
        return empty
    where, params = build_filters(args)
    base = "FROM incidents i JOIN areas a ON a.id=i.area_id JOIN incident_types t ON t.id=i.type_id"

    # Area x hour grid (for the heat grid) and type x slot (for the stacked chart)
    area_names = [a["name"] for a in s["by_area"]]
    grid = {n: [0] * 24 for n in area_names}
    for r in query(f"SELECT a.name an, i.hour_of_day h, COUNT(*) c {base} WHERE {where} GROUP BY a.id, h", params):
        grid[r["an"]][r["h"]] = r["c"]
    area_hour = {"areas": area_names, "grid": [grid[n] for n in area_names],
                 "max": max((max(v) for v in grid.values()), default=0)}
    ts = {}
    for r in query(f"SELECT t.name tn, {SLOT_SQL} s, COUNT(*) c {base} WHERE {where} GROUP BY t.id, s", params):
        ts.setdefault(r["tn"], [0] * 4)[SLOTS.index(r["s"])] = r["c"]
    type_names = [t["name"] for t in s["by_type"]]
    type_slot = {"types": type_names, "slots": SLOTS, "data": [ts.get(n, [0] * 4) for n in type_names]}

    peak_by_area = [dict(r) for r in query(f"""
        SELECT area, hour, c FROM (
            SELECT a.name area, i.hour_of_day hour, COUNT(*) c,
                   ROW_NUMBER() OVER (PARTITION BY a.id ORDER BY COUNT(*) DESC, i.hour_of_day) rn
            {base} WHERE {where} GROUP BY a.id, i.hour_of_day) WHERE rn = 1
        ORDER BY c DESC""", params)]

    tbs = {r["slot"]: dict(r) for r in query(f"""
        SELECT slot, name, c FROM (
            SELECT {SLOT_SQL} slot, t.name name, COUNT(*) c,
                   ROW_NUMBER() OVER (PARTITION BY {SLOT_SQL} ORDER BY COUNT(*) DESC) rn
            {base} WHERE {where} GROUP BY {SLOT_SQL}, t.id) WHERE rn = 1""", params)}
    type_by_slot = [tbs[sl] for sl in SLOTS if sl in tbs]

    sbs = {r["slot"]: dict(r) for r in query(f"""
        SELECT {SLOT_SQL} slot, ROUND(AVG(t.severity), 2) avg_sev, COUNT(*) c
        {base} WHERE {where} GROUP BY {SLOT_SQL}""", params)}
    sev_by_slot = [sbs[sl] for sl in SLOTS if sl in sbs]

    trend = []
    for r in query(f"""
        SELECT a.name area,
               SUM(i.incident_time >= date('now', '-30 day')) last30,
               SUM(i.incident_time <  date('now', '-30 day') AND i.incident_time >= date('now', '-60 day')) prev30
        {base} WHERE {where} GROUP BY a.id""", params):
        trend.append({"area": r["area"], "last30": r["last30"] or 0, "prev30": r["prev30"] or 0,
                      "change": (r["last30"] or 0) - (r["prev30"] or 0)})
    trend.sort(key=lambda x: x["change"], reverse=True)

    k, areas, types = s["kpis"], s["by_area"], s["by_type"]
    sl, wk = s["by_slot"], s["by_weekday"]
    night, evening = sl[3], sl[2]
    F = []

    # WHAT
    pts = [f"{t['name']}: {t['incidents']} cases ({pct(t['incidents'], total)}%)" for t in types[:3]]
    pts.append(f"{k['severe']} cases ({pct(k['severe'], total)}%) are severe (severity 4-5).")
    F.append({"icon": "📋", "heading": "What is happening", "points": pts})

    # WHERE
    top3 = areas[:3]
    pts = [f"{a['name']}: {a['incidents']} incidents ({pct(a['incidents'], total)}%), risk level {a['level']}" for a in top3]
    pts.append(f"The top {len(top3)} areas together account for {pct(sum(a['incidents'] for a in top3), total)}% of all incidents.")
    if len(areas) > 3:
        pts.append(f"Lowest incident count: {areas[-1]['name']} ({areas[-1]['incidents']}).")
    F.append({"icon": "📍", "heading": "Where it happens", "points": pts})

    # WHEN
    pts = []
    if k["peak_hour"] is not None:
        pts.append(f"Peak hour is {k['peak_hour']:02d}:00-{(k['peak_hour'] + 1) % 24:02d}:00.")
    top_slot = sl.index(max(sl))
    pts.append(f"{SLOTS[top_slot]} is the riskiest time slot ({pct(sl[top_slot], total)}% of incidents).")
    pts.append(f"Night (10PM-5AM) has {pct(night, total)}% and Evening (5PM-10PM) has {pct(evening, total)}% of incidents.")
    wd_avg, we_avg = sum(wk[:5]) / 5, sum(wk[5:]) / 2
    if wd_avg and we_avg:
        pts.append(f"Weekends average {we_avg:.0f} incidents/day vs {wd_avg:.0f} on weekdays "
                   f"({'higher' if we_avg > wd_avg else 'lower'} on weekends).")
    pts.append(f"Busiest day of the week: {DAYS[wk.index(max(wk))]}.")
    F.append({"icon": "🕒", "heading": "When it happens", "points": pts})

    # HOW - patterns
    pts = []
    best = max(((m["area"], SLOTS[i], c) for m in s["matrix"] for i, c in enumerate(m["counts"])), key=lambda x: x[2])
    pts.append(f"Biggest hotspot combination: {best[0]} during {best[1]} ({best[2]} incidents, {pct(best[2], total)}% of all).")
    night_peak = [p for p in peak_by_area if p["hour"] >= 22 or p["hour"] < 5]
    if night_peak:
        pts.append("Areas whose peak hour falls at night: " + ", ".join(p["area"] for p in night_peak[:4]) + ".")
    for r in type_by_slot:
        pts.append(f"In {r['slot']}, the most common incident is {r['name']} ({r['c']} cases).")
    if sev_by_slot:
        worst = max(sev_by_slot, key=lambda x: x["avg_sev"])
        pts.append(f"Incidents are most severe during {worst['slot']} (average severity {worst['avg_sev']}/5).")
    F.append({"icon": "🔍", "heading": "How it happens (patterns)", "points": pts})

    # TREND
    pts = []
    last, prev = sum(t["last30"] for t in trend), sum(t["prev30"] for t in trend)
    if prev:
        ch = round(100 * (last - prev) / prev)
        pts.append(f"Last 30 days: {last} incidents vs {prev} in the previous 30 days ({ch:+d}%).")
    else:
        pts.append(f"Last 30 days: {last} incidents (no data for the previous 30 days to compare).")
    rising = [t for t in trend if t["change"] > 0][:3]
    falling = [t for t in reversed(trend) if t["change"] < 0][:3]
    if rising:
        pts.append("Rising: " + ", ".join(f"{t['area']} (+{t['change']})" for t in rising) + ".")
    if falling:
        pts.append("Improving: " + ", ".join(f"{t['area']} ({t['change']})" for t in falling) + ".")
    F.append({"icon": "📈", "heading": "Trend", "points": pts})

    # WHY - hypotheses only
    pts = []
    if pct(night, total) >= 30:
        pts.append("A large share of incidents happen at night: check street lighting, patrol coverage and late-night transport safety.")
    if pct(evening, total) >= 30:
        pts.append("Many incidents occur in the evening rush: check crowding, market/transport hubs and last-mile walking routes.")
    if we_avg > wd_avg * 1.15:
        pts.append("Weekends are busier: check events, nightlife areas and reduced patrolling on weekends.")
    if k["resolution_rate"] < 50:
        pts.append(f"Only {k['resolution_rate']}% of cases are resolved: follow-up capacity may be a gap.")
    if top3 and pct(sum(a["incidents"] for a in top3), total) >= 50:
        pts.append("Incidents are concentrated in a few areas: targeted measures there can reduce overall risk quickly.")
    if not pts:
        pts.append("No strong single pattern stands out in this selection.")
    pts.append("Note: these are possible factors to investigate on the ground. The data shows where and when, not the cause.")
    F.append({"icon": "💡", "heading": "Possible reasons to investigate", "points": pts})

    # ACTIONS
    pts = []
    if top3:
        pts.append(f"Prioritise patrols and CCTV in {', '.join(a['name'] for a in top3)} during {SLOTS[top_slot]}.")
    pts.append("Improve lighting and safe-route signage around the top hotspots.")
    if k["open"]:
        pts.append(f"Review the {k['open']} open cases and close stale ones to raise the resolution rate.")
    pts.append("Run awareness drives and promote helplines 112 and 1091 in high-risk areas.")
    F.append({"icon": "✅", "heading": "Suggested actions", "points": pts})

    return {"total": total, "findings": F, "peak_by_area": peak_by_area, "trend": trend,
            "type_by_slot": type_by_slot, "sev_by_slot": sev_by_slot, "area_hour": area_hour,
            "type_slot": type_slot, "stats": s}


@app.route("/analysis")
@login_required
def analysis():
    areas, types = lookups()
    return render_template("analysis.html", areas=areas, types=types, statuses=STATUSES, slots=SLOTS,
                           f=request.args, can_export=g.user["role"] in ("admin", "officer"))


@app.route("/api/analysis")
@login_required
def api_analysis():
    return jsonify(compute_analysis(request.args))


# --------------------------------------------------------------------------- report exports (PDF / Excel)
def _filters_text(args):
    return ", ".join(f"{k}={v}" for k, v in args.items() if v and k != "page") or "none (all data)"


def _export_rows(args):
    where, params = build_filters(args)
    return query(f"""SELECT i.id, i.incident_time, a.name area, t.name type, t.severity, i.status,
                            i.latitude, i.longitude, i.description
                     FROM incidents i JOIN areas a ON a.id=i.area_id JOIN incident_types t ON t.id=i.type_id
                     WHERE {where} ORDER BY i.incident_time DESC""", params)


@app.route("/reports/export.pdf")
@roles_required("admin", "officer")
def export_pdf():
    from xml.sax.saxutils import escape
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    an = compute_analysis(request.args)
    s = an["stats"]
    k = s["kpis"]
    ss = getSampleStyleSheet()

    def table(data, widths=None):
        t = Table(data, repeatRows=1, colWidths=widths)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4f46e5")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")])]))
        return t

    story = [Paragraph("Women's Safety Incident Report", ss["Title"]),
             Paragraph(f"Generated {datetime.now():%d %b %Y, %H:%M} &nbsp;|&nbsp; Filters: {escape(_filters_text(request.args))}", ss["BodyText"]),
             Spacer(1, 10),
             table([["Total incidents", "Severe (4-5)", "Open cases", "Resolution rate", "Peak hour"],
                    [k["total"], k["severe"], k["open"], f"{k['resolution_rate']}%",
                     "-" if k["peak_hour"] is None else f"{k['peak_hour']:02d}:00"]]),
             Spacer(1, 12)]

    if an["total"]:
        from reportlab.graphics.charts.barcharts import HorizontalBarChart, VerticalBarChart
        from reportlab.graphics.charts.piecharts import Pie
        from reportlab.graphics.shapes import Drawing

        def hbar(names, vals, color):
            h = 22 * len(names) + 30
            d = Drawing(500, h)
            c = HorizontalBarChart()
            c.x, c.y, c.width, c.height = 110, 12, 360, h - 24
            c.data = [list(reversed(vals))]
            c.categoryAxis.categoryNames = list(reversed(names))
            c.categoryAxis.labels.fontSize = 7
            c.valueAxis.labels.fontSize = 7
            c.valueAxis.valueMin = 0
            c.bars[0].fillColor = colors.HexColor(color)
            c.barLabelFormat = "%d"
            c.barLabels.fontSize = 7
            c.barLabels.nudge = 8
            d.add(c)
            return d

        def vbar(names, vals, color):
            d = Drawing(500, 170)
            c = VerticalBarChart()
            c.x, c.y, c.width, c.height = 30, 25, 450, 125
            c.data = [vals]
            c.categoryAxis.categoryNames = names
            c.categoryAxis.labels.fontSize = 6
            c.valueAxis.labels.fontSize = 7
            c.valueAxis.valueMin = 0
            c.bars[0].fillColor = colors.HexColor(color)
            d.add(c)
            return d

        story.append(Paragraph("Charts", ss["Heading2"]))
        from reportlab.platypus import KeepTogether

        def chart_block(title, drawing):          # keep a heading together with its chart
            story.append(KeepTogether([Paragraph(f"<b>{title}</b>", ss["BodyText"]), drawing]))

        chart_block("Incidents by area",
                    hbar([a["name"] for a in s["by_area"]], [a["incidents"] for a in s["by_area"]], "#dc2626"))
        chart_block("Incidents by hour of day", vbar([f"{h:02d}" for h in range(24)], s["by_hour"], "#4f46e5"))
        if sum(s["by_slot"]):
            pd = Drawing(500, 150)
            pie = Pie()
            pie.x, pie.y, pie.width, pie.height = 190, 20, 110, 110
            pie.data = s["by_slot"]
            pie.labels = [f"{SLOTS[i].split(' ')[0]} ({v})" for i, v in enumerate(s["by_slot"])]
            pie.sideLabels = 1
            pie.slices.strokeWidth = 0.5
            pie.slices.fontSize = 7
            for i, col in enumerate(["#0891b2", "#d97706", "#7c3aed", "#dc2626"]):
                pie.slices[i].fillColor = colors.HexColor(col)
            pd.add(pie)
            chart_block("Incidents by time slot", pd)
        chart_block("Incidents by day of week", vbar(DAYS, s["by_weekday"], "#0891b2"))
        chart_block("Incident types",
                    hbar([t["name"] for t in s["by_type"]], [t["incidents"] for t in s["by_type"]], "#d97706"))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Analysis: what, where, when and how", ss["Heading2"]))
        for fnd in an["findings"]:
            story.append(Paragraph(f"<b>{escape(fnd['heading'])}</b>", ss["BodyText"]))
            for p in fnd["points"]:
                story.append(Paragraph("&bull; " + escape(p), ss["BodyText"]))
            story.append(Spacer(1, 6))
        story.append(Paragraph("Area-wise analysis", ss["Heading2"]))
        story.append(table([["#", "Area", "Incidents", "Risk score", "Resolved %", "Level"]] +
                           [[i + 1, a["name"], a["incidents"], a["risk_score"], f"{a['resolved_pct']}%", a["level"]]
                            for i, a in enumerate(s["by_area"])]))
        story.append(Spacer(1, 10))
        story.append(Paragraph("Area x time-slot matrix", ss["Heading2"]))
        story.append(table([["Area", "Morning", "Afternoon", "Evening", "Night"]] +
                           [[m["area"]] + m["counts"] for m in s["matrix"]]))
        story.append(Spacer(1, 10))
        story.append(Paragraph("Time-wise analysis", ss["Heading2"]))
        story.append(table([["Time slot", "Incidents", "Share"]] +
                           [[SLOTS[i], c, f"{pct(c, an['total'])}%"] for i, c in enumerate(s["by_slot"])]))
        story.append(Spacer(1, 6))
        story.append(table([["Day"] + DAYS, ["Incidents"] + s["by_weekday"]]))
        story.append(Spacer(1, 10))
        story.append(Paragraph("Incident types", ss["Heading2"]))
        story.append(table([["Type", "Severity", "Incidents"]] +
                           [[t["name"], f"{t['severity']}/5", t["incidents"]] for t in s["by_type"]]))
    else:
        story.append(Paragraph("No incidents match the selected filters.", ss["BodyText"]))

    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36,
                      title="Women's Safety Incident Report").build(story)
    return Response(buf.getvalue(), mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=safety_report_{datetime.now():%Y%m%d_%H%M}.pdf"})


@app.route("/reports/export.xlsx")
@roles_required("admin", "officer")
def export_xlsx():
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    from openpyxl.utils import get_column_letter

    an = compute_analysis(request.args)
    s = an["stats"]
    wb = Workbook()
    ws0 = wb.active
    ws0.title = "Summary"

    def fill(ws, header, rows):
        ws.append(header)
        for c in ws[1]:
            c.font = Font(bold=True, color="FFFFFF")
            c.fill = PatternFill("solid", fgColor="4F46E5")
        for r in rows:
            ws.append(list(r))
        for idx in range(1, len(header) + 1):
            width = max(len(str(c.value or "")) for c in ws[get_column_letter(idx)])
            ws.column_dimensions[get_column_letter(idx)].width = min(width + 3, 60)

    k = s["kpis"]
    fill(ws0, ["Metric", "Value"], [
        ("Generated", f"{datetime.now():%Y-%m-%d %H:%M}"), ("Filters", _filters_text(request.args)),
        ("Total incidents", k["total"]), ("Severe (4-5)", k["severe"]), ("Open cases", k["open"]),
        ("Resolution rate %", k["resolution_rate"]), ("Peak hour", k["peak_hour"]), ("Top hotspot", k["top_area"])])
    ws0.append([])
    ws0.append(["Analysis findings"])
    ws0.cell(ws0.max_row, 1).font = Font(bold=True)
    for fnd in an["findings"]:
        ws0.append([fnd["heading"]])
        ws0.cell(ws0.max_row, 1).font = Font(bold=True)
        for p in fnd["points"]:
            ws0.append(["", p])
    from openpyxl.chart import BarChart, LineChart, Reference

    def add_chart(ws, kind, title, value_col, anchor, horizontal=False):
        """Native Excel chart from a sheet filled by fill(): categories in col 1, values in value_col."""
        if ws.max_row < 2:
            return
        ch = LineChart() if kind == "line" else BarChart()
        if kind == "bar":
            ch.type = "bar" if horizontal else "col"
        ch.title, ch.legend = title, None
        ch.height, ch.width = 9, 18
        ch.add_data(Reference(ws, min_col=value_col, min_row=1, max_row=ws.max_row), titles_from_data=True)
        ch.set_categories(Reference(ws, min_col=1, min_row=2, max_row=ws.max_row))
        ws.add_chart(ch, anchor)

    ws = wb.create_sheet("Areas")
    fill(ws, ["Area", "Incidents", "Risk score", "Resolved %", "Level"],
         [(a["name"], a["incidents"], a["risk_score"], a["resolved_pct"], a["level"]) for a in s["by_area"]])
    add_chart(ws, "bar", "Incidents by area", 2, "H2", horizontal=True)
    fill(wb.create_sheet("Area x Time slot"), ["Area"] + SLOTS, [[m["area"]] + m["counts"] for m in s["matrix"]])
    ws = wb.create_sheet("By hour")
    fill(ws, ["Hour", "Incidents"], [(f"{h:02d}:00", c) for h, c in enumerate(s["by_hour"])])
    add_chart(ws, "bar", "Incidents by hour of day", 2, "D2")
    ws = wb.create_sheet("By weekday")
    fill(ws, ["Day", "Incidents"], list(zip(DAYS, s["by_weekday"])))
    add_chart(ws, "bar", "Incidents by day of week", 2, "D2")
    ws = wb.create_sheet("Types")
    fill(ws, ["Type", "Severity", "Incidents"], [(t["name"], t["severity"], t["incidents"]) for t in s["by_type"]])
    add_chart(ws, "bar", "Incidents by type", 3, "F2", horizontal=True)
    ws = wb.create_sheet("Trend")
    fill(ws, ["Month", "Incidents"], [(t["month"], t["incidents"]) for t in s["trend"]])
    add_chart(ws, "line", "Monthly trend", 2, "D2")
    fill(wb.create_sheet("Incidents"),
         ["ID", "Incident time", "Area", "Type", "Severity", "Status", "Latitude", "Longitude", "Description"],
         [tuple(r) for r in _export_rows(request.args)])
    buf = io.BytesIO()
    wb.save(buf)
    return Response(buf.getvalue(),
                    mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f"attachment; filename=safety_report_{datetime.now():%Y%m%d_%H%M}.xlsx"})


# --------------------------------------------------------------------------- Power BI export
POWERBI_DIR = os.path.join(BASE, "powerbi")
POWERBI_FILES = {"POWERBI_GUIDE.md", "measures.dax", "safety_theme.json", "load_from_db.py"}


def slot_for_hour(h):
    return SLOTS[3] if h >= 22 or h < 5 else SLOTS[0] if h < 12 else SLOTS[1] if h < 17 else SLOTS[2]


def powerbi_tables():
    """Star schema for Power BI: one fact table and four dimensions. No personal data is included."""
    rows = query("""SELECT i.id, i.incident_time, i.hour_of_day, i.day_of_week, i.area_id, i.type_id,
                           t.severity, i.status, i.latitude, i.longitude
                    FROM incidents i JOIN incident_types t ON t.id = i.type_id ORDER BY i.id""")
    fact = [[r["id"], r["incident_time"][:10], r["incident_time"], r["hour_of_day"], slot_for_hour(r["hour_of_day"]),
             r["day_of_week"] + 1, r["area_id"], r["type_id"], r["severity"], r["status"],
             1 if r["status"] in ("Reported", "Under Review") else 0, 1 if r["severity"] >= 4 else 0,
             r["latitude"], r["longitude"]] for r in rows]
    fact_head = ["incident_id", "incident_date", "incident_datetime", "hour", "time_slot", "weekday_no", "area_id",
                 "type_id", "severity", "status", "is_open", "is_severe", "latitude", "longitude"]

    dates = []
    if rows:
        d0 = datetime.strptime(min(r["incident_time"][:10] for r in rows), "%Y-%m-%d").date()
        d1 = datetime.strptime(max(r["incident_time"][:10] for r in rows), "%Y-%m-%d").date()
        d = d0
        while d <= d1:
            dates.append([d.isoformat(), d.year, d.month, d.strftime("%B"), d.strftime("%Y-%m"), d.day,
                          d.weekday() + 1, d.strftime("%A"), 1 if d.weekday() >= 5 else 0])
            d += timedelta(days=1)
    return {
        "fact_incidents": (fact_head, fact),
        "dim_area": (["area_id", "area_name", "city", "latitude", "longitude"],
                     [list(r) for r in query("SELECT id, name, city, lat, lng FROM areas ORDER BY id")]),
        "dim_type": (["type_id", "type_name", "severity"],
                     [list(r) for r in query("SELECT id, name, severity FROM incident_types ORDER BY id")]),
        "dim_date": (["date", "year", "month_no", "month_name", "year_month", "day", "weekday_no", "weekday_name",
                      "is_weekend"], dates),
        "dim_hour": (["hour", "hour_label", "time_slot", "slot_order"],
                     [[h, f"{h:02d}:00", slot_for_hour(h), SLOTS.index(slot_for_hour(h)) + 1] for h in range(24)]),
    }


@app.route("/powerbi")
@roles_required("admin", "officer")
def powerbi():
    t = powerbi_tables()
    return render_template("powerbi.html", tables={k: (v[0], len(v[1])) for k, v in t.items()})


@app.route("/powerbi/export.zip")
@roles_required("admin", "officer")
def powerbi_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, (head, rows) in powerbi_tables().items():
            sio = io.StringIO()
            w = csv.writer(sio)
            w.writerow(head)
            w.writerows(rows)
            z.writestr(f"{name}.csv", "﻿" + sio.getvalue())     # BOM so Excel/Power BI read UTF-8 correctly
        for fname in ("POWERBI_GUIDE.md", "measures.dax", "safety_theme.json"):
            z.write(os.path.join(POWERBI_DIR, fname), fname)
    return Response(buf.getvalue(), mimetype="application/zip",
                    headers={"Content-Disposition": f"attachment; filename=powerbi_data_{datetime.now():%Y%m%d}.zip"})


@app.route("/powerbi/export.xlsx")
@roles_required("admin", "officer")
def powerbi_xlsx():
    from openpyxl import Workbook
    from openpyxl.styles import Font
    wb = Workbook()
    wb.remove(wb.active)
    for name, (head, rows) in powerbi_tables().items():
        ws = wb.create_sheet(name)
        ws.append(head)
        for c in ws[1]:
            c.font = Font(bold=True)
        for r in rows:
            ws.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    return Response(buf.getvalue(),
                    mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f"attachment; filename=powerbi_data_{datetime.now():%Y%m%d}.xlsx"})


@app.route("/powerbi/files/<name>")
@roles_required("admin", "officer")
def powerbi_file(name):
    if name not in POWERBI_FILES:
        abort(404)
    return send_from_directory(POWERBI_DIR, name, as_attachment=True)


# --------------------------------------------------------------------------- inquiries
INQUIRY_CATEGORIES = ["Case status", "Safety concern", "General question", "Suggestion", "Other"]
INQUIRY_STATUSES = ["Open", "Answered", "Closed"]


def inquiry_counts():
    r = query("""SELECT COUNT(*) total, COALESCE(SUM(status='Open'),0) open_n,
                        COALESCE(SUM(status='Answered'),0) answered, COALESCE(SUM(status='Closed'),0) closed
                 FROM inquiries""", one=True)
    return dict(r)


def get_inquiry_or_404(iid):
    row = query("""SELECT q.*, u.name asker, u.email asker_email, r.name responder
                   FROM inquiries q JOIN users u ON u.id = q.user_id LEFT JOIN users r ON r.id = q.replied_by
                   WHERE q.id = ?""", (iid,), one=True)
    if row is None or (g.user["role"] == "citizen" and row["user_id"] != g.user["id"]):
        abort(404)
    return row


@app.route("/inquiries")
@login_required
def inquiries_list():
    status = request.args.get("status", "")
    where, params = ["1=1"], []
    if g.user["role"] == "citizen":
        where.append("q.user_id = ?"); params.append(g.user["id"])
    if status in INQUIRY_STATUSES:
        where.append("q.status = ?"); params.append(status)
    rows = query(f"""SELECT q.*, u.name asker FROM inquiries q JOIN users u ON u.id = q.user_id
                     WHERE {' AND '.join(where)} ORDER BY (q.status = 'Open') DESC, q.created_at DESC""", params)
    return render_template("inquiries.html", rows=rows, status=status, statuses=INQUIRY_STATUSES,
                           counts=inquiry_counts() if g.user["role"] != "citizen" else None)


@app.route("/inquiries/new", methods=["GET", "POST"])
@login_required
def inquiry_new():
    if request.method == "POST":
        f = request.form
        subject, message = f.get("subject", "").strip(), f.get("message", "").strip()
        category = f.get("category")
        errors = []
        if category not in INQUIRY_CATEGORIES:
            errors.append("Select a category.")
        if len(subject) < 3 or len(subject) > 120:
            errors.append("Subject must be 3 to 120 characters.")
        if len(message) < 10 or len(message) > 2000:
            errors.append("Message must be 10 to 2000 characters.")
        inc_id = None
        if f.get("incident_id", "").strip():
            if not f["incident_id"].strip().isdigit():
                errors.append("Incident ID must be a number.")
            else:
                inc = query("SELECT id, user_id FROM incidents WHERE id = ?", (int(f["incident_id"]),), one=True)
                if not inc or (g.user["role"] == "citizen" and inc["user_id"] != g.user["id"]):
                    errors.append("That incident ID was not found among your reports.")
                else:
                    inc_id = inc["id"]
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("inquiry_new.html", categories=INQUIRY_CATEGORIES, f=f), 400
        cur = execute("""INSERT INTO inquiries (user_id, incident_id, category, subject, message)
                         VALUES (?,?,?,?,?)""", (g.user["id"], inc_id, category, subject, message))
        flash(f"Inquiry #{cur.lastrowid} submitted. You will see the reply here.", "success")
        return redirect(url_for("inquiry_detail", iid=cur.lastrowid))
    return render_template("inquiry_new.html", categories=INQUIRY_CATEGORIES, f=request.args)


@app.route("/inquiries/<int:iid>")
@login_required
def inquiry_detail(iid):
    return render_template("inquiry_detail.html", q=get_inquiry_or_404(iid))


@app.route("/inquiries/<int:iid>/reply", methods=["POST"])
@roles_required("admin", "officer")
def inquiry_reply(iid):
    get_inquiry_or_404(iid)
    reply = request.form.get("reply", "").strip()
    if len(reply) < 3 or len(reply) > 2000:
        flash("Reply must be 3 to 2000 characters.", "danger")
        return redirect(url_for("inquiry_detail", iid=iid))
    execute("""UPDATE inquiries SET reply = ?, status = 'Answered', replied_by = ?, replied_at = datetime('now')
               WHERE id = ?""", (reply, g.user["id"], iid))
    flash("Reply sent.", "success")
    return redirect(url_for("inquiry_detail", iid=iid))


@app.route("/inquiries/<int:iid>/close", methods=["POST"])
@login_required
def inquiry_close(iid):
    get_inquiry_or_404(iid)
    execute("UPDATE inquiries SET status = 'Closed' WHERE id = ?", (iid,))
    flash("Inquiry closed.", "info")
    return redirect(url_for("inquiry_detail", iid=iid))


# --------------------------------------------------------------------------- safe journey planner
# Unique feature: pick a start area, a destination and a departure time. The planner scores every
# area on the way for the hour you will actually be there, suggests a safer route (via another
# area) and the safest time to leave, plus tips based on what is reported along that route.
ROAD_FACTOR = 1.3          # straight-line km -> approximate road km
JOURNEY_SPEED_KMH = 20.0   # average urban travel speed
CORRIDOR_KM = 1.5          # areas within this distance of the route line count as "on the way"
MAX_DETOUR = 1.5           # alternative routes may be at most 50% longer than the direct one


def risk_band(score):
    return "High" if score >= 66 else "Medium" if score >= 33 else "Low"


def _xy(lat, lng, lat0):
    return lng * math.cos(math.radians(lat0)) * 111.32, lat * 110.57


def _km(a, b):
    ax, ay = _xy(a["lat"], a["lng"], a["lat"])
    bx, by = _xy(b["lat"], b["lng"], a["lat"])
    return math.hypot(ax - bx, ay - by)


def _along(p, a, b):
    """(t, distance_km) of point p projected on segment a-b (t in 0..1)."""
    px, py = _xy(p["lat"], p["lng"], a["lat"])
    ax, ay = _xy(a["lat"], a["lng"], a["lat"])
    bx, by = _xy(b["lat"], b["lng"], a["lat"])
    dx, dy = bx - ax, by - ay
    t = 0 if dx == dy == 0 else max(0, min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return t, math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def hourly_risk_table():
    """{area_id: [risk index 0-100 for each hour]} - severity-weighted, smoothed over +-1 hour.
    Rejected reports are ignored. The index is relative to the busiest area-hour in the data."""
    raw = {}
    for r in query("""SELECT i.area_id aid, i.hour_of_day h, SUM(t.severity) s
                      FROM incidents i JOIN incident_types t ON t.id = i.type_id
                      WHERE i.status != 'Rejected' GROUP BY i.area_id, i.hour_of_day"""):
        raw.setdefault(r["aid"], [0] * 24)[r["h"]] = r["s"]
    smooth = {aid: [(v[(h - 1) % 24] + v[h] + v[(h + 1) % 24]) / 3 for h in range(24)]
              for aid, v in raw.items()}
    top = max((max(v) for v in smooth.values()), default=0)
    return {aid: [round(100 * x / top) if top else 0 for x in v] for aid, v in smooth.items()}


def _stops_for(waypoints, areas):
    """Ordered list of areas along start -> (via) -> destination, incl. areas close to the line."""
    stops = [waypoints[0]]
    for p, q in zip(waypoints, waypoints[1:]):
        mids = []
        for a in areas:
            if a["id"] in (p["id"], q["id"]) or any(a["id"] == s["id"] for s in stops):
                continue
            t, d = _along(a, p, q)
            if d <= CORRIDOR_KM and 0 < t < 1:
                mids.append((t, a))
        stops += [a for _, a in sorted(mids, key=lambda m: m[0])]
        if not any(q["id"] == s["id"] for s in stops):
            stops.append(q)
    return stops


def _score_route(stops, table, dep_hour):
    """Risk of travelling through `stops` when leaving at dep_hour (float hours)."""
    legs = [_km(a, b) * ROAD_FACTOR for a, b in zip(stops, stops[1:])]
    cum, out = 0.0, []
    for i, s in enumerate(stops):
        if i:
            cum += legs[i - 1]
        hour = int((dep_hour + cum / JOURNEY_SPEED_KMH) % 24)
        risk = table.get(s["id"], [0] * 24)[hour]
        out.append({"id": s["id"], "name": s["name"], "lat": s["lat"], "lng": s["lng"],
                    "risk": risk, "level": risk_band(risk), "hour": hour})
    risks = [s["risk"] for s in out]
    score = round(0.6 * sum(risks) / len(risks) + 0.4 * max(risks))
    return {"stops": out, "distance_km": round(cum, 1), "minutes": round(cum / JOURNEY_SPEED_KMH * 60),
            "risk": score, "level": risk_band(score)}


def plan_journey(from_id, to_id, when):
    areas = [dict(a) for a in query("SELECT * FROM areas ORDER BY name")]
    by_id = {a["id"]: a for a in areas}
    start, end = by_id[from_id], by_id[to_id]
    table = hourly_risk_table()
    dep = when.hour + when.minute / 60

    direct_stops = _stops_for([start, end], areas)
    direct = dict(_score_route(direct_stops, table, dep), label="Direct route", via=None)
    direct_len = _km(start, end)

    options, seen = [direct], {tuple(s["id"] for s in direct_stops)}
    for w in areas:
        if w["id"] in (from_id, to_id) or _km(start, w) + _km(w, end) > MAX_DETOUR * direct_len:
            continue
        stops = _stops_for([start, w, end], areas)
        key = tuple(s["id"] for s in stops)
        if key in seen:
            continue
        seen.add(key)
        options.append(dict(_score_route(stops, table, dep), label=f"Via {w['name']}", via=w["name"]))
    options.sort(key=lambda o: (o["risk"], o["distance_km"]))
    best = options[0] if direct["risk"] - options[0]["risk"] >= 5 else direct
    alternatives = [o for o in options if o is not best][:3]

    # Safest time to leave (same route, every departure hour of the day)
    best_ids = [s["id"] for s in best["stops"]]
    best_areas = [by_id[i] for i in best_ids]
    hourly = [_score_route(best_areas, table, h)["risk"] for h in range(24)]
    now_h = when.hour
    window = [(now_h + k) % 24 for k in range(12)]
    best_h = min(window, key=lambda h: (hourly[h], (h - now_h) % 24))
    leave = {"hourly": hourly, "best_hour": best_h, "best_risk": hourly[best_h],
             "better": hourly[now_h] - hourly[best_h] >= 5}

    # What is reported along this route around this time (+-2h)?
    marks = ",".join("?" * len(best_ids))
    hrs = [(now_h + k) % 24 for k in range(-2, 3)]
    common = [dict(r) for r in query(
        f"""SELECT t.name, COUNT(*) c FROM incidents i JOIN incident_types t ON t.id = i.type_id
            WHERE i.status != 'Rejected' AND i.area_id IN ({marks}) AND i.hour_of_day IN ({",".join("?" * 5)})
            GROUP BY t.id ORDER BY c DESC LIMIT 3""", best_ids + hrs)]

    tips = ["Share your live location with someone you trust before you start, and tell them your ETA.",
            "Keep your phone charged and the emergency numbers handy: 112 (emergency), 1091 (women helpline)."]
    if best["level"] != "Low":
        tips.append("Prefer well-lit main roads and busy stops; avoid shortcuts through empty lanes.")
        tips.append("Use a registered cab/auto or a metro/bus with other passengers, and check the number plate.")
    if best["level"] == "High":
        tips.append("Consider travelling with someone, or use the suggested safer departure time below.")
    if now_h >= 21 or now_h < 5:
        tips.append("It is late: wait for your ride at a lit, staffed place (shop, station, hotel lobby).")
    for c in common[:2]:
        tips.append(f"{c['name']} is among the most reported incidents on this route around this hour; stay alert.")

    top_hot = max(best["stops"], key=lambda s: s["risk"])
    return {"from": start["name"], "to": end["name"], "departure": when.strftime("%Y-%m-%d %H:%M"),
            "recommended": best, "alternatives": alternatives, "direct": direct,
            "is_direct": best is direct, "leave": leave, "reported_here": common, "tips": tips,
            "hotspot": {"name": top_hot["name"], "risk": top_hot["risk"]},
            "note": "Risk index 0-100 is relative to the busiest area-hour in the reported data; "
                    "it reflects reporting patterns, not a guarantee of safety."}


@app.route("/journey")
@login_required
def journey():
    areas, _types = lookups()
    return render_template("journey.html", areas=areas, f=request.args,
                           now=datetime.now().strftime("%Y-%m-%dT%H:%M"))


@app.route("/api/journey")
@login_required
def api_journey():
    ids = {a["id"] for a in query("SELECT id FROM areas")}
    f = request.args.get("from", ""), request.args.get("to", "")
    if not all(x.isdigit() and int(x) in ids for x in f):
        return jsonify(error="Choose a valid start and destination."), 400
    if f[0] == f[1]:
        return jsonify(error="Start and destination must be different."), 400
    raw = request.args.get("when", "")
    try:
        when = datetime.strptime(raw, "%Y-%m-%dT%H:%M") if raw else datetime.now()
    except ValueError:
        return jsonify(error="Enter a valid departure date and time."), 400
    return jsonify(plan_journey(int(f[0]), int(f[1]), when))


# --------------------------------------------------------------------------- trip guardian
# A "safety buddy" timer: the user starts a trip with an expected duration and a trusted contact.
# The contact gets a private tracking link (no login). If the user does not tap "I'm safe" before
# the deadline the trip becomes OVERDUE and appears on the officers' alert board. SOS is one tap.
TRIP_FMT = "%Y-%m-%d %H:%M:%S"
EXTEND_MINUTES = 15
MAX_EXTENSIONS = 4
PHONE_RE = re.compile(r"^\+?\d{10,13}$")
TRIP_SELECT = """SELECT t.*, fa.name from_name, ta.name to_name, u.name user_name
                 FROM trips t JOIN areas fa ON fa.id = t.from_area_id
                 JOIN areas ta ON ta.id = t.to_area_id JOIN users u ON u.id = t.user_id"""


def trip_state(row):
    """Adds the live state: Active / Overdue / SOS / Safe / Cancelled and seconds remaining."""
    remaining = int((datetime.strptime(row["deadline"], TRIP_FMT) - datetime.now()).total_seconds())
    label = row["status"]
    if label == "Active" and remaining < 0:
        label = "Overdue"
    d = dict(row)
    d.update(label=label, remaining=remaining, overdue_min=max(0, -remaining // 60),
             live=row["status"] in ("Active", "SOS"))
    return d


def get_own_trip_or_404(tid):
    row = query(TRIP_SELECT + " WHERE t.id = ? AND t.user_id = ?", (tid, g.user["id"]), one=True)
    if row is None:
        abort(404)
    return row


@app.route("/guardian")
@login_required
def guardian():
    areas, _types = lookups()
    rows = [trip_state(r) for r in query(TRIP_SELECT + " WHERE t.user_id = ? ORDER BY t.id DESC LIMIT 6",
                                         (g.user["id"],))]
    current = next((r for r in rows if r["live"]), None)
    link = url_for("track", token=current["token"], _external=True) if current else None
    return render_template("guardian.html", areas=areas, current=current, history=rows, link=link,
                           f=request.args, max_ext=MAX_EXTENSIONS, ext_min=EXTEND_MINUTES)


@app.route("/guardian/start", methods=["POST"])
@login_required
def guardian_start():
    f = request.form
    errors = []
    ids = {a["id"] for a in query("SELECT id FROM areas")}
    frm, to = f.get("from_area_id", ""), f.get("to_area_id", "")
    if not (frm.isdigit() and to.isdigit() and int(frm) in ids and int(to) in ids):
        errors.append("Choose a valid start and destination.")
    elif frm == to:
        errors.append("Start and destination must be different.")
    minutes = int(f["minutes"]) if f.get("minutes", "").isdigit() else 0
    if not 5 <= minutes <= 720:
        errors.append("Expected travel time must be between 5 and 720 minutes.")
    cname = f.get("contact_name", "").strip()[:60]
    phone = re.sub(r"[\s-]", "", f.get("contact_phone", ""))
    if len(cname) < 2:
        errors.append("Enter your trusted contact's name.")
    if not PHONE_RE.match(phone):
        errors.append("Enter a valid contact phone number (10-13 digits).")
    if query("SELECT 1 FROM trips WHERE user_id = ? AND status IN ('Active','SOS')", (g.user["id"],), one=True):
        errors.append("You already have a trip in progress. Finish it first.")
    if errors:
        for e in errors:
            flash(e, "danger")
        return redirect(url_for("guardian", **{"from": frm, "to": to, "minutes": f.get("minutes", "")}))
    now = datetime.now()
    execute("""INSERT INTO trips (user_id, from_area_id, to_area_id, contact_name, contact_phone, note,
                                  token, started_at, deadline) VALUES (?,?,?,?,?,?,?,?,?)""",
            (g.user["id"], int(frm), int(to), cname, phone, f.get("note", "").strip()[:200],
             secrets.token_urlsafe(16), now.strftime(TRIP_FMT),
             (now + timedelta(minutes=minutes)).strftime(TRIP_FMT)))
    flash("Trip Guardian is ON. Send the tracking link to your trusted contact and travel safely!", "success")
    return redirect(url_for("guardian"))


@app.route("/guardian/<int:tid>/<action>", methods=["POST"])
@login_required
def guardian_action(tid, action):
    t = get_own_trip_or_404(tid)
    if action not in ("safe", "extend", "sos", "cancel"):
        abort(404)
    if t["status"] not in ("Active", "SOS"):
        flash("This trip is already finished.", "info")
        return redirect(url_for("guardian"))
    now = datetime.now()
    if action == "safe":
        execute("UPDATE trips SET status='Safe', ended_at=? WHERE id=?", (now.strftime(TRIP_FMT), tid))
        flash("Glad you reached safely! Your contact will see you are safe.", "success")
    elif action == "cancel":
        execute("UPDATE trips SET status='Cancelled', ended_at=? WHERE id=?", (now.strftime(TRIP_FMT), tid))
        flash("Trip cancelled.", "info")
    elif action == "sos":
        execute("UPDATE trips SET status='SOS' WHERE id=?", (tid,))
        flash("SOS raised. Officers and your contact can see it. If you are in danger call 112 now.", "danger")
    else:  # extend
        if t["status"] != "Active":
            flash("An SOS trip cannot be extended. Tap 'I'm safe' when you are safe.", "warning")
        elif t["extended_count"] >= MAX_EXTENSIONS:
            flash(f"You can extend a trip at most {MAX_EXTENSIONS} times.", "warning")
        else:
            base = max(now, datetime.strptime(t["deadline"], TRIP_FMT))
            execute("UPDATE trips SET deadline=?, extended_count=extended_count+1 WHERE id=?",
                    ((base + timedelta(minutes=EXTEND_MINUTES)).strftime(TRIP_FMT), tid))
            flash(f"Deadline extended by {EXTEND_MINUTES} minutes.", "success")
    return redirect(url_for("guardian"))


def _public_trip(token):
    row = query(TRIP_SELECT + " WHERE t.token = ?", (token,), one=True)
    if row is None:
        abort(404)
    t = trip_state(row)
    return {"traveller": row["user_name"].split()[0], "from": row["from_name"], "to": row["to_name"],
            "status": t["label"], "remaining": t["remaining"], "overdue_min": t["overdue_min"],
            "started_at": row["started_at"][:16], "deadline": row["deadline"][11:16],
            "note": row["note"] or ""}


@app.route("/track/<token>")
def track(token):
    return render_template("track.html", t=_public_trip(token), token=token)


@app.route("/track/<token>/status.json")
def track_status(token):
    return jsonify(_public_trip(token))


@app.route("/guardian/alerts")
@roles_required("admin", "officer")
def guardian_alerts():
    rows = [trip_state(r) for r in query(TRIP_SELECT + " WHERE t.status IN ('Active','SOS')")]
    alerts = [r for r in rows if r["label"] in ("SOS", "Overdue")]
    alerts.sort(key=lambda r: (r["label"] != "SOS", r["remaining"]))
    active = sorted((r for r in rows if r["label"] == "Active"), key=lambda r: r["remaining"])
    return render_template("guardian_alerts.html", alerts=alerts, active=active)


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, msg="You do not have permission to view this page."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, msg="Page not found."), 404


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, msg=getattr(e, "description", "Bad request.")), 400


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        import seed_data
        seed_data.seed()
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=5000)
