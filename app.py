"""
app.py  —  SPA Flask REST API
Install deps:  pip install flask flask-cors mysql-connector-python bcrypt
Run:           python app.py
"""

from flask import Flask, request, jsonify, session
from flask_cors import CORS
import mysql.connector
import bcrypt
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = 'spa-secret-key-change-this-in-production'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_DOMAIN'] = '127.0.0.1'
CORS(app, supports_credentials=True, origins=["http://127.0.0.1:5000"])  # tighten in production

# ── DB CONFIG ─────────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     "localhost",
    "user":     "root",        # ← your MySQL username
    "password": "",            # ← your MySQL password
    "database": "spa_db",
}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

# ── AUTH HELPERS ──────────────────────────────────────────────────────────────
def login_required(roles=None):
    """Decorator: checks session, optionally restricts to role list."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({"error": "Not authenticated"}), 401
            if roles and session.get("role") not in roles:
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

def audit(action, details=""):
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute(
            "INSERT INTO audit_log (user_id, actor, action, details) VALUES (%s, %s, %s, %s)",
            (session.get("user_id"), session.get("username"), action, details)
        )
        conn.commit(); cur.close(); conn.close()
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    username = (data.get("username") or "").strip().lower()
    password = (data.get("password") or "")
    role     = (data.get("role") or "").strip()

    if not username or not password or not role:
        return jsonify({"error": "All fields required"}), 400

    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT * FROM users WHERE LOWER(username)=%s AND role=%s AND is_active=1",
        (username, role)
    )
    user = cur.fetchone(); cur.close(); conn.close()

    if not user or not bcrypt.checkpw(password.encode(), user["pwd_hash"].encode()):
        audit("LOGIN_FAIL", f"username={username}")
        return jsonify({"error": "Invalid credentials"}), 401

    # Store session
    session["user_id"]  = user["id"]
    session["username"] = user["username"]
    session["role"]     = user["role"]
    session["must_change_pwd"] = bool(user["must_change_pwd"])

    audit("LOGIN_SUCCESS", f"role={role}")

    return jsonify({
        "id":              user["id"],
        "username":        user["username"],
        "role":            user["role"],
        "must_change_pwd": bool(user["must_change_pwd"]),
    })


@app.route("/api/logout", methods=["POST"])
@login_required()
def logout():
    audit("LOGOUT", f"username={session.get('username')}")
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/change-password", methods=["POST"])
@login_required()
def change_password():
    """
    Called when:
      - User is force-changing temp password (must_change_pwd=1), OR
      - User voluntarily changes password
    Body: { current_password, new_password }
    """
    data        = request.json or {}
    current_pw  = data.get("current_password", "")
    new_pw      = data.get("new_password", "")

    if len(new_pw) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400

    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
    user = cur.fetchone()

    if not user or not bcrypt.checkpw(current_pw.encode(), user["pwd_hash"].encode()):
        cur.close(); conn.close()
        return jsonify({"error": "Current password is incorrect"}), 401

    new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    cur.execute(
        "UPDATE users SET pwd_hash=%s, must_change_pwd=0 WHERE id=%s",
        (new_hash, session["user_id"])
    )
    conn.commit(); cur.close(); conn.close()

    session["must_change_pwd"] = False
    audit("PASSWORD_CHANGED", "")
    return jsonify({"ok": True})


@app.route("/api/me", methods=["GET"])
@login_required()
def me():
    """Returns current session info — used on page load to re-hydrate state."""
    return jsonify({
        "id":              session["user_id"],
        "username":        session["username"],
        "role":            session["role"],
        "must_change_pwd": session.get("must_change_pwd", False),
    })


# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN — USER MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/users", methods=["GET"])
@login_required(roles=["admin"])
def list_users():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT u.id, u.username, u.role, u.is_active, u.must_change_pwd,
               u.created_at, c.username AS created_by_name
        FROM users u
        LEFT JOIN users c ON u.created_by = c.id
        ORDER BY u.id
    """)
    users = cur.fetchall(); cur.close(); conn.close()
    # never send hashes
    return jsonify(users)


@app.route("/api/users", methods=["POST"])
@login_required(roles=["admin","faculty"])
def create_user():
    """
    Admin creates a faculty or student account with a temporary password.
    Body: { username, temp_password, role, full_name?, department? }
    """
    data      = request.json or {}
    username  = (data.get("username") or "").strip()
    temp_pw   = (data.get("temp_password") or "")
    role      = (data.get("role") or "").strip()
    subject = (data.get("subject") or "").strip()
    dept    = (data.get("department") or "").strip()
    full_name = (data.get("full_name") or "").strip()
    dept      = (data.get("department") or "").strip()

    allowed_roles = ["faculty", "student", "admin"] if session.get("role") == "admin" else ["student"]
    if not username or not temp_pw or role not in allowed_roles:
        return jsonify({"error": "username, temp_password, and valid role required"}), 400
    if len(temp_pw) < 6:
        return jsonify({"error": "Temp password must be at least 6 characters"}), 400
    if role == "student" and (not full_name or not dept):
        return jsonify({"error": "full_name and department required for students"}), 400

    pwd_hash = bcrypt.hashpw(temp_pw.encode(), bcrypt.gensalt()).decode()

    conn = get_db(); cur = conn.cursor(dictionary=True)

    # Check duplicate username
    cur.execute("SELECT id FROM users WHERE LOWER(username)=%s", (username.lower(),))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({"error": "Username already exists"}), 409

    cur.execute(
    "INSERT INTO users (username, pwd_hash, role, must_change_pwd, created_by, subject, department) VALUES (%s,%s,%s,1,%s,%s,%s)",
    (username, pwd_hash, role, session["user_id"], subject or None, dept or None)
)
    new_user_id = cur.lastrowid

    # If student, create student record
    if role == "student":
        cur.execute(
            "INSERT INTO students (user_id, full_name, department) VALUES (%s,%s,%s)",
            (new_user_id, full_name, dept)
        )

    conn.commit()
    audit("CREATE_USER", f"username={username} role={role}")
    cur.close(); conn.close()
    return jsonify({"ok": True, "user_id": new_user_id}), 201


@app.route("/api/users/<int:uid>/toggle", methods=["POST"])
@login_required(roles=["admin"])
def toggle_user(uid):
    if uid == session["user_id"]:
        return jsonify({"error": "Cannot disable yourself"}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("UPDATE users SET is_active = 1 - is_active WHERE id=%s", (uid,))
    conn.commit()
    cur.execute("SELECT is_active, username FROM users WHERE id=%s", (uid,))
    row = cur.fetchone(); cur.close(); conn.close()
    audit("TOGGLE_USER", f"user_id={uid} active→{row[0]}")
    return jsonify({"is_active": row[0], "username": row[1]})


@app.route("/api/users/<int:uid>/reset-password", methods=["POST"])
@login_required(roles=["admin"])
def admin_reset_password(uid):
    """Admin sets a new temp password → must_change_pwd flips back to 1."""
    data    = request.json or {}
    new_pw  = data.get("new_password", "")
    if len(new_pw) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    pwd_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT username FROM users WHERE id=%s", (uid,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return jsonify({"error": "User not found"}), 404

    cur.execute(
        "UPDATE users SET pwd_hash=%s, must_change_pwd=1 WHERE id=%s",
        (pwd_hash, uid)
    )
    conn.commit(); cur.close(); conn.close()
    audit("ADMIN_RESET_PASSWORD", f"target_user_id={uid} username={row['username']}")
    return jsonify({"ok": True})
@app.route("/api/forgot-password/verify", methods=["POST"])
def forgot_verify():
    data     = request.json or {}
    username = (data.get("username") or "").strip().lower()
    answer   = (data.get("answer") or "").strip().lower()

    if not username or not answer:
        return jsonify({"error": "Username and answer required"}), 400

    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, security_answer FROM users WHERE LOWER(username)=%s AND is_active=1", (username,))
    user = cur.fetchone(); cur.close(); conn.close()

    if not user or not user["security_answer"]:
        return jsonify({"error": "User not found or no security answer set"}), 404

    if user["security_answer"].strip().lower() != answer:
        return jsonify({"error": "Incorrect answer"}), 401

    session["reset_user_id"] = user["id"]
    return jsonify({"ok": True})


@app.route("/api/forgot-password/reset", methods=["POST"])
def forgot_reset():
    if "reset_user_id" not in session:
        return jsonify({"error": "Not verified"}), 401

    data   = request.json or {}
    new_pw = data.get("new_password", "")
    if len(new_pw) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    pwd_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    uid = session.pop("reset_user_id")

    conn = get_db(); cur = conn.cursor()
    cur.execute("UPDATE users SET pwd_hash=%s, must_change_pwd=0 WHERE id=%s", (pwd_hash, uid))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})


@app.route("/api/me/security-answer", methods=["POST"])
@login_required()
def set_security_answer():
    data   = request.json or {}
    answer = (data.get("answer") or "").strip()
    if not answer:
        return jsonify({"error": "Answer required"}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("UPDATE users SET security_answer=%s WHERE id=%s", (answer, session["user_id"]))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})
@app.route("/api/forgot-password/request", methods=["POST"])
def forgot_request():
    """Anyone can call this — no login needed."""
    data     = request.json or {}
    username = (data.get("username") or "").strip().lower()
    role     = (data.get("role") or "").strip()

    if not username or not role:
        return jsonify({"error": "Username and role required"}), 400

    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, username, role FROM users WHERE LOWER(username)=%s AND role=%s AND is_active=1", (username, role))
    user = cur.fetchone()
    if not user:
        cur.close(); conn.close()
        return jsonify({"error": "User not found"}), 404

    # Check if already pending
    cur.execute("SELECT id FROM pwd_reset_requests WHERE user_id=%s AND status='pending'", (user["id"],))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({"error": "Request already pending — please contact admin"}), 409

    cur.execute(
        "INSERT INTO pwd_reset_requests (user_id, username, role) VALUES (%s,%s,%s)",
        (user["id"], user["username"], user["role"])
    )
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})


@app.route("/api/pwd-reset-requests", methods=["GET"])
@login_required(roles=["admin"])
def get_reset_requests():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT * FROM pwd_reset_requests 
        WHERE status='pending' 
        ORDER BY requested_at DESC
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        for k, v in r.items():
            if hasattr(v, 'isoformat'): r[k] = str(v)
    return jsonify(rows)


@app.route("/api/pwd-reset-requests/<int:rid>/resolve", methods=["POST"])
@login_required(roles=["admin"])
def resolve_reset_request(rid):
    conn = get_db(); cur = conn.cursor()
    cur.execute("UPDATE pwd_reset_requests SET status='resolved' WHERE id=%s", (rid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})



# ══════════════════════════════════════════════════════════════════════════════
#  STUDENTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/students", methods=["GET"])
@login_required(roles=["admin", "faculty"])
def list_students():
    dept = request.args.get("department", "")
    conn = get_db(); cur = conn.cursor(dictionary=True)
    if dept:
        cur.execute("""
            SELECT s.id, s.full_name, s.department, s.enrolled_at, u.username,
                   COALESCE(AVG(sm.marks), 0) AS avg_marks
            FROM students s
            JOIN users u ON s.user_id = u.id
            LEFT JOIN subject_marks sm ON sm.student_id = s.id
            WHERE s.department = %s
            GROUP BY s.id
            ORDER BY avg_marks DESC
        """, (dept,))
    else:
        cur.execute("""
            SELECT s.id, s.full_name, s.department, s.enrolled_at, u.username,
                   COALESCE(AVG(sm.marks), 0) AS avg_marks
            FROM students s
            JOIN users u ON s.user_id = u.id
            LEFT JOIN subject_marks sm ON sm.student_id = s.id
            GROUP BY s.id
            ORDER BY avg_marks DESC
        """)
    students = cur.fetchall(); cur.close(); conn.close()
    return jsonify(students)


@app.route("/api/students/<int:sid>", methods=["GET"])
@login_required()
def get_student(sid):
    """
    Admins/faculty can fetch any student.
    Students can only fetch their own record.
    """
    conn = get_db(); cur = conn.cursor(dictionary=True)

    if session["role"] == "student":
        # verify ownership
        cur.execute("SELECT id FROM students WHERE id=%s AND user_id=%s", (sid, session["user_id"]))
        if not cur.fetchone():
            cur.close(); conn.close()
            return jsonify({"error": "Forbidden"}), 403

    cur.execute("""
        SELECT s.id, s.full_name, s.department, s.enrolled_at,
               u.username, u.id AS user_id
        FROM students s JOIN users u ON s.user_id = u.id
        WHERE s.id = %s
    """, (sid,))
    student = cur.fetchone()
    if not student:
        cur.close(); conn.close()
        return jsonify({"error": "Not found"}), 404

    cur.execute("SELECT subject, marks FROM subject_marks WHERE student_id=%s", (sid,))
    subjects = {r["subject"]: float(r["marks"]) for r in cur.fetchall()}
    student["subjects"] = subjects
    student["avg_marks"] = round(sum(subjects.values()) / len(subjects), 2) if subjects else 0

    cur.close(); conn.close()
    return jsonify(student)


@app.route("/api/students/me", methods=["GET"])
@login_required(roles=["student"])
def my_student_record():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT s.id, s.full_name, s.department, s.enrolled_at,
               COALESCE(AVG(sm.marks),0) AS avg_marks
        FROM students s
        LEFT JOIN subject_marks sm ON sm.student_id = s.id
        WHERE s.user_id = %s
        GROUP BY s.id
    """, (session["user_id"],))
    student = cur.fetchone()
    if not student:
        cur.close(); conn.close()
        return jsonify({"error": "No student record linked to this account"}), 404

    cur.execute("""
        SELECT subject, marks,
               COALESCE(internal_marks, 0) AS internal_marks,
               COALESCE(external_marks, 0) AS external_marks
        FROM subject_marks WHERE student_id=%s
    """, (student["id"],))
    student["subjects"] = {
        r["subject"]: {
            "marks":    float(r["marks"]),
            "internal": float(r["internal_marks"]),
            "external": float(r["external_marks"])
        } for r in cur.fetchall()
    }
    cur.close(); conn.close()
    return jsonify(student)


@app.route("/api/students/<int:sid>", methods=["PUT"])
@login_required(roles=["admin", "faculty"])
def update_student(sid):
    data      = request.json or {}
    full_name = (data.get("full_name") or "").strip()
    dept      = (data.get("department") or "").strip()
    enrolled  = (data.get("enrolled_at") or "").strip()
    subjects  = data.get("subjects", {})

    conn = get_db(); cur = conn.cursor()

    # Build dynamic update
    fields, vals = [], []
    if full_name: fields.append("full_name=%s"); vals.append(full_name)
    if dept:      fields.append("department=%s"); vals.append(dept)
    if enrolled:  fields.append("enrolled_at=%s"); vals.append(enrolled)

    if fields:
        vals.append(sid)
        cur.execute(f"UPDATE students SET {','.join(fields)} WHERE id=%s", vals)

    # Upsert subject marks
    for subj, marks in subjects.items():
        marks = min(max(float(marks), 0), 100)
        cur.execute("""
            INSERT INTO subject_marks (student_id, subject, marks)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE marks=%s
        """, (sid, subj, marks, marks))

    conn.commit(); cur.close(); conn.close()
    audit("UPDATE_STUDENT", f"student_id={sid}")
    return jsonify({"ok": True})

@app.route("/api/students/<int:sid>", methods=["DELETE"])
@login_required(roles=["admin"])
def delete_student(sid):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT full_name FROM students WHERE id=%s", (sid,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return jsonify({"error": "Not found"}), 404
    cur.execute("DELETE FROM students WHERE id=%s", (sid,))
    conn.commit(); cur.close(); conn.close()
    audit("DELETE_STUDENT", f"student_id={sid} name={row[0]}")
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════════════════════════════════
#  ANALYTICS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/analytics/overview", methods=["GET"])
@login_required(roles=["admin", "faculty","student"])
def analytics_overview():
    conn = get_db(); cur = conn.cursor(dictionary=True)

    # Per-department stats
    cur.execute("""
        SELECT s.department,
               COUNT(DISTINCT s.id)        AS student_count,
               ROUND(AVG(sm.marks), 2)     AS avg_marks,
               MAX(sm.marks)               AS max_marks,
               MIN(sm.marks)               AS min_marks
        FROM students s
        LEFT JOIN subject_marks sm ON sm.student_id = s.id
        GROUP BY s.department
        ORDER BY avg_marks DESC
    """)
    dept_stats = cur.fetchall()

    # All students with avg
    cur.execute("""
        SELECT s.id, s.full_name, s.department,
               ROUND(COALESCE(AVG(sm.marks),0),2) AS avg_marks
        FROM students s
        LEFT JOIN subject_marks sm ON sm.student_id = s.id
        GROUP BY s.id
        ORDER BY avg_marks DESC
    """)
    all_students = cur.fetchall()

    cur.close(); conn.close()
    return jsonify({"dept_stats": dept_stats, "students": all_students})


@app.route("/api/analytics/bonus", methods=["POST"])
@login_required(roles=["admin", "faculty"])
def add_bonus():
    data  = request.json or {}
    dept  = (data.get("department") or "").strip()
    bonus = float(data.get("bonus", 0))
    if not dept or bonus <= 0:
        return jsonify({"error": "department and positive bonus required"}), 400

    conn = get_db(); cur = conn.cursor()
    cur.execute("""
        UPDATE subject_marks sm
        JOIN students s ON sm.student_id = s.id
        SET sm.marks = LEAST(sm.marks + %s, 100)
        WHERE s.department = %s
    """, (bonus, dept))
    rows = cur.rowcount
    conn.commit(); cur.close(); conn.close()
    audit("ADD_BONUS", f"dept={dept} bonus={bonus} rows_affected={rows}")
    return jsonify({"ok": True, "rows_updated": rows})


# ══════════════════════════════════════════════════════════════════════════════
#  AUDIT LOG
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/audit-log", methods=["GET"])
@login_required(roles=["admin"])
def get_audit_log():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 50")
    logs = cur.fetchall(); cur.close(); conn.close()
    return jsonify(logs)

@app.route("/api/users/<int:uid>", methods=["DELETE"])
@login_required(roles=["admin"])
def delete_user(uid):
    if uid == session["user_id"]:
        return jsonify({"error": "Cannot delete yourself"}), 400
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT username, role FROM users WHERE id=%s", (uid,))
    user = cur.fetchone()
    if not user:
        cur.close(); conn.close()
        return jsonify({"error": "User not found"}), 404
    cur.execute("DELETE FROM users WHERE id=%s", (uid,))
    conn.commit(); cur.close(); conn.close()
    audit("DELETE_USER", f"username={user['username']} role={user['role']}")
    return jsonify({"ok": True})

@app.route('/')
def index():
    return app.send_static_file('dashboard.html')
@app.route("/api/students/<int:sid>/bonus", methods=["POST"])
@login_required(roles=["admin", "faculty"])
def student_bonus(sid):
    data  = request.json or {}
    bonus = float(data.get("bonus", 0))
    if bonus <= 0:
        return jsonify({"error": "Bonus must be positive"}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("""
        UPDATE subject_marks
        SET marks = LEAST(marks + %s, 100)
        WHERE student_id = %s
    """, (bonus, sid))
    rows = cur.rowcount
    conn.commit(); cur.close(); conn.close()
    audit("INDIVIDUAL_BONUS", f"student_id={sid} bonus={bonus} rows={rows}")
    return jsonify({"ok": True, "rows_updated": rows})
# ══════════════════════════════════════════════════════════════════════════════
# ── ATTENDANCE ROUTES ────────────────────────────────────────

@app.route("/api/attendance", methods=["GET"])
@login_required(roles=["admin", "faculty", "student"])
def get_attendance():
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    role = session["role"]

    # STUDENT VIEW
    if role == "student":
        cur.execute("""
            SELECT a.date, a.status,
                COUNT(*) OVER () AS total,
                SUM(CASE WHEN a.status='present' THEN 1 ELSE 0 END)
                OVER () AS present_count
            FROM attendance a
            JOIN students s ON s.id = a.student_id
            WHERE s.user_id = %s
            ORDER BY a.date DESC LIMIT 15
        """, (session["user_id"],))

    # ADMIN / FACULTY VIEW
    else:
        sid = request.args.get("student_id")

        # FILTER BY STUDENT
        if sid:
            cur.execute("""
                SELECT a.date, a.status, s.full_name
                FROM attendance a
                JOIN students s ON s.id = a.student_id
                WHERE a.student_id = %s
                ORDER BY a.date DESC LIMIT 15
            """, (sid,))

        else:
            date_filter = request.args.get("date", "")

            # FILTER BY DATE
            if date_filter:
                cur.execute("""
                    SELECT a.date, a.status, s.full_name, s.department
                    FROM attendance a
                    JOIN students s ON s.id = a.student_id
                    WHERE a.date = %s
                    ORDER BY s.full_name
                """, (date_filter,))

            # OVERALL ATTENDANCE REPORT
            else:
                cur.execute("""
                    SELECT 
                        s.id AS student_id,
                        s.full_name,
                        s.department,
                        COUNT(a.id) AS total_days,
                        SUM(CASE WHEN a.status='present' THEN 1 ELSE 0 END) AS present_count,
                        ROUND(
                            SUM(CASE WHEN a.status='present' THEN 1 ELSE 0 END)
                            / NULLIF(COUNT(a.id),0) * 100,
                            1
                        ) AS attendance_pct
                    FROM students s
                    LEFT JOIN attendance a ON a.student_id = s.id
                    GROUP BY s.id, s.full_name, s.department
                    ORDER BY attendance_pct ASC
                """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify(rows)
@app.route("/api/attendance", methods=["POST"])
@login_required(roles=["admin", "faculty"])
def mark_attendance():
    data       = request.json or {}
    student_id = data.get("student_id")
    date       = data.get("date")
    status     = data.get("status", "present")

    if not student_id or not date:
        return jsonify({"error": "student_id and date required"}), 400
    if status not in ("present", "absent"):
        return jsonify({"error": "status must be present or absent"}), 400

    conn = get_db(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO attendance (student_id, date, status)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE status = %s
    """, (student_id, date, status, status))
    conn.commit(); cur.close(); conn.close()
    audit("MARK_ATTENDANCE", f"student_id={student_id} date={date} status={status}")
    return jsonify({"ok": True})

# ── NOTIFICATIONS ────────────────────────────────────────────

@app.route("/api/notifications", methods=["GET"])
@login_required(roles=["admin", "faculty"])
def get_notifications():
    conn = get_db(); cur = conn.cursor(dictionary=True)

    # Departments with avg < 40
    cur.execute("""
        SELECT s.department,
               ROUND(AVG(sm.marks), 1) AS avg_marks,
               COUNT(DISTINCT s.id)    AS student_count
        FROM students s
        JOIN subject_marks sm ON sm.student_id = s.id
        GROUP BY s.department
        HAVING avg_marks < 40
    """)
    low_depts = cur.fetchall()

    # Individual students failing (avg < 40)
    cur.execute("""
        SELECT s.id, s.full_name, s.department,
               ROUND(AVG(sm.marks), 1) AS avg_marks
        FROM students s
        JOIN subject_marks sm ON sm.student_id = s.id
        GROUP BY s.id, s.full_name, s.department
        HAVING avg_marks < 40
        ORDER BY avg_marks ASC
        LIMIT 10
    """)
    failing = cur.fetchall()

    cur.close(); conn.close()
    notifications = []
    for d in low_depts:
        notifications.append({
            "type": "alert",
            "msg":  f"Dept {d['department']} avg is {d['avg_marks']} — below 40!",
            "dept": d["department"]
        })
    for s in failing:
        notifications.append({
            "type":    "warning",
            "msg":     f"{s['full_name']} ({s['department']}) is failing with avg {s['avg_marks']}",
            "student_id": s["id"]
        })
    return jsonify(notifications)


# ── RANKINGS (uses VIEW) ──────────────────────────────────────
@app.route("/api/rankings", methods=["GET"])
@login_required(roles=["admin", "faculty", "student"])
def get_rankings():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM student_rank_view ORDER BY overall_rank")
    rows = cur.fetchall(); cur.close(); conn.close()
    # Convert date objects to string
    result = []
    for row in rows:
        new_row = {}
        for k, v in row.items():
            new_row[k] = v.isoformat() if hasattr(v, 'isoformat') else v
        result.append(new_row)
    return jsonify(result)


@app.route("/api/students/<int:sid>/report-card", methods=["GET"])
@login_required(roles=["admin", "faculty", "student"])
def report_card(sid):
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM student_rank_view WHERE id=%s", (sid,))
    student = cur.fetchone()
    if not student:
        cur.close(); conn.close()
        return jsonify({"error": "Not found"}), 404
    for k, v in student.items():
        if hasattr(v, 'isoformat'):
            student[k] = v.isoformat()
    cur.execute(
        "SELECT subject, marks FROM subject_marks WHERE student_id=%s ORDER BY subject",
        (sid,)
    )
    subjects = cur.fetchall()
    cur.close(); conn.close()
    return jsonify({**student, "subjects": subjects})
@app.route("/api/notifications/attendance", methods=["GET"])
@login_required(roles=["admin", "faculty", "student"])
def attendance_notifications():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    notifications = []

    if session["role"] == "student":
        # Only 
        #  THIS student their own low-attendance warning
        cur.execute("""
            SELECT
                COUNT(a.id) AS total_days,
                ROUND(
                    SUM(CASE WHEN a.status='present' THEN 1 ELSE 0 END)
                    / NULLIF(COUNT(a.id), 0) * 100, 1
                ) AS attendance_pct
            FROM attendance a
            JOIN students s ON s.id = a.student_id
            WHERE s.user_id = %s
        """, (session["user_id"],))
        row = cur.fetchone()
        if row and row["total_days"] and row["attendance_pct"] is not None and row["attendance_pct"] < 75:
            notifications.append({
                "type": "warning",
                "msg": f"⚠️ Your attendance is {row['attendance_pct']}% — below the 75% minimum!"
            })
    else:
        # Admin/faculty see all students below 75%
        cur.execute("""
            SELECT s.full_name, s.department,
                COUNT(a.id) AS total_days,
                ROUND(
                    SUM(CASE WHEN a.status='present' THEN 1 ELSE 0 END)
                    / NULLIF(COUNT(a.id), 0) * 100, 1
                ) AS attendance_pct
            FROM students s
            LEFT JOIN attendance a ON a.student_id = s.id
            GROUP BY s.id, s.full_name, s.department
            HAVING total_days > 0 AND attendance_pct < 75
            ORDER BY attendance_pct ASC
        """)
        for s in cur.fetchall():
            notifications.append({
                "type": "warning",
                "msg": f"{s['full_name']} ({s['department']}) attendance is {s['attendance_pct']}%"
            })

    cur.close(); conn.close()
    return jsonify(notifications)
# ══════════════════════════════════════════════════════════════════════════════
#  SEMESTER-WISE MARKS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/students/<int:sid>/subject-marks", methods=["POST"])
@login_required(roles=["faculty"])
def update_subject_marks(sid):
    data     = request.json or {}
    subject  = (data.get("subject") or "").strip()
    internal = float(data.get("internal_marks", 0))
    external = float(data.get("external_marks", 0))
    semester = int(data.get("semester", 1))

    if not subject:
        return jsonify({"error": "subject required"}), 400
    internal = min(max(internal, 0), 40)
    external = min(max(external, 0), 60)
    total    = internal + external

    conn = get_db(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO subject_marks (student_id, subject, internal_marks, external_marks, marks, semester)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            internal_marks=%s, external_marks=%s, marks=%s
    """, (sid, subject, internal, external, total, semester,
          internal, external, total))
    conn.commit(); cur.close(); conn.close()
    audit("UPDATE_MARKS", f"student_id={sid} subject={subject} sem={semester} total={total}")
    return jsonify({"ok": True, "total": total})


@app.route("/api/students/<int:sid>/progress", methods=["GET"])
@login_required()
def student_progress(sid):
    """Returns semester-wise marks for progress graph."""
    conn = get_db(); cur = conn.cursor(dictionary=True)

    if session["role"] == "student":
        cur.execute("SELECT id FROM students WHERE id=%s AND user_id=%s", (sid, session["user_id"]))
        if not cur.fetchone():
            cur.close(); conn.close()
            return jsonify({"error": "Forbidden"}), 403

    cur.execute("""
        SELECT semester, subject, marks, internal_marks, external_marks
        FROM subject_marks
        WHERE student_id=%s
        ORDER BY semester, subject
    """, (sid,))
    rows = cur.fetchall()
    cur.close(); conn.close()

    # Group by semester → avg marks per semester
    from collections import defaultdict
    sem_data = defaultdict(list)
    for r in rows:
        sem_data[r["semester"]].append({
            "subject": r["subject"],
            "marks": float(r["marks"]),
            "internal": float(r["internal_marks"] or 0),
            "external": float(r["external_marks"] or 0),
        })

    result = []
    for sem in sorted(sem_data.keys()):
        subjects = sem_data[sem]
        avg = round(sum(s["marks"] for s in subjects) / len(subjects), 2) if subjects else 0
        result.append({"semester": sem, "avg_marks": avg, "subjects": subjects})

    return jsonify(result)


# ══════════════════════════════════════════════════════════════════════════════
#  TIMETABLE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/timetable", methods=["GET"])
@login_required()
def get_timetable():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    day_order = "CASE day_of_week WHEN 'Monday' THEN 1 WHEN 'Tuesday' THEN 2 WHEN 'Wednesday' THEN 3 WHEN 'Thursday' THEN 4 WHEN 'Friday' THEN 5 WHEN 'Saturday' THEN 6 ELSE 7 END"
    cols = "id, department, day_of_week, TIME_FORMAT(start_time,'%H:%i') AS start_time, TIME_FORMAT(end_time,'%H:%i') AS end_time, subject, faculty, room, created_by, created_at"
    if session["role"] == "student":
        cur.execute("SELECT department FROM students WHERE user_id=%s", (session["user_id"],))
        row = cur.fetchone()
        if not row:
            cur.close(); conn.close()
            return jsonify([])
        dept = row["department"]
        cur.execute(f"SELECT {cols} FROM timetable WHERE department=%s ORDER BY {day_order}, start_time", (dept,))
    else:
        dept = request.args.get("department", "")
        if dept:
            cur.execute(f"SELECT {cols} FROM timetable WHERE department=%s ORDER BY {day_order}, start_time", (dept,))
        else:
            cur.execute(f"SELECT {cols} FROM timetable ORDER BY department, {day_order}, start_time")

    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        for k, v in r.items():
            if hasattr(v, 'isoformat'):
                r[k] = str(v)
    return jsonify(rows)

@app.route("/api/timetable", methods=["POST"])
@login_required(roles=["admin", "faculty"])
def add_timetable():
    data = request.json or {}
    dept    = (data.get("department") or "").strip()
    day     = (data.get("day_of_week") or "").strip()
    start   = (data.get("start_time") or "").strip()
    end     = (data.get("end_time") or "").strip()
    subject = (data.get("subject") or "").strip()
    faculty = (data.get("faculty") or "").strip()
    room    = (data.get("room") or "").strip()

    if not all([dept, day, start, end, subject]):
        return jsonify({"error": "department, day, start_time, end_time, subject required"}), 400

    conn = get_db(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO timetable (department, day_of_week, start_time, end_time, subject, faculty, room, created_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
    """, (dept, day, start, end, subject, faculty, room, session["user_id"]))
    conn.commit()
    new_id = cur.lastrowid
    cur.close(); conn.close()
    audit("ADD_TIMETABLE", f"dept={dept} day={day} subject={subject}")
    return jsonify({"ok": True, "id": new_id}), 201


@app.route("/api/timetable/<int:tid>", methods=["DELETE"])
@login_required(roles=["admin", "faculty"])
def delete_timetable(tid):
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM timetable WHERE id=%s", (tid,))
    conn.commit(); cur.close(); conn.close()
    audit("DELETE_TIMETABLE", f"id={tid}")
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════════════════════════════════
#  ASSIGNMENTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/assignments", methods=["GET"])
@login_required()
def get_assignments():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    if session["role"] == "student":
        cur.execute("SELECT department FROM students WHERE user_id=%s", (session["user_id"],))
        row = cur.fetchone()
        dept = row["department"] if row else ""
        cur.execute("""
            SELECT a.*, 
                   (SELECT COUNT(*) FROM assignment_submissions s WHERE s.assignment_id=a.id AND s.student_id=(
                       SELECT id FROM students WHERE user_id=%s
                   )) AS submitted
            FROM assignments a
            WHERE a.department=%s
            ORDER BY a.due_date ASC
        """, (session["user_id"], dept))
    else:
        dept = request.args.get("department", "")
        if dept:
            cur.execute("SELECT * FROM assignments WHERE department=%s ORDER BY due_date ASC", (dept,))
        else:
            cur.execute("SELECT * FROM assignments ORDER BY due_date ASC")
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        for k, v in r.items():
            if hasattr(v, 'isoformat'):
                r[k] = str(v)
    return jsonify(rows)


@app.route("/api/assignments", methods=["POST"])
@login_required(roles=["faculty"])
def create_assignment():
    data = request.json or {}
    dept     = (data.get("department") or "").strip()
    subject  = (data.get("subject") or "").strip()
    title    = (data.get("title") or "").strip()
    desc     = (data.get("description") or "").strip()
    due_date = (data.get("due_date") or "").strip()

    if not all([dept, subject, title, due_date]):
        return jsonify({"error": "department, subject, title, due_date required"}), 400

    conn = get_db(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO assignments (department, subject, title, description, due_date, created_by)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (dept, subject, title, desc, due_date, session["user_id"]))
    conn.commit()
    new_id = cur.lastrowid
    cur.close(); conn.close()
    audit("CREATE_ASSIGNMENT", f"dept={dept} title={title} due={due_date}")
    return jsonify({"ok": True, "id": new_id}), 201


@app.route("/api/assignments/<int:aid>", methods=["DELETE"])
@login_required(roles=["faculty"])
def delete_assignment(aid):
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM assignments WHERE id=%s", (aid,))
    conn.commit(); cur.close(); conn.close()
    audit("DELETE_ASSIGNMENT", f"id={aid}")
    return jsonify({"ok": True})


@app.route("/api/assignments/<int:aid>/submit", methods=["POST"])
@login_required(roles=["student"])
def submit_assignment(aid):
    data = request.json or {}
    text = (data.get("submission") or "").strip()
    if not text:
        return jsonify({"error": "submission text required"}), 400

    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id FROM students WHERE user_id=%s", (session["user_id"],))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return jsonify({"error": "Student record not found"}), 404

    sid = row["id"]
    cur.execute("""
        INSERT INTO assignment_submissions (assignment_id, student_id, submission, status)
        VALUES (%s,%s,%s,'submitted')
        ON DUPLICATE KEY UPDATE submission=%s, submitted_at=NOW(), status='submitted'
    """, (aid, sid, text, text))
    conn.commit(); cur.close(); conn.close()
    audit("SUBMIT_ASSIGNMENT", f"assignment_id={aid} student_id={sid}")
    return jsonify({"ok": True})


@app.route("/api/assignments/<int:aid>/submissions", methods=["GET"])
@login_required(roles=["faculty"])
def get_submissions(aid):
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT s.full_name, s.department, sub.submission, sub.submitted_at, sub.status
        FROM assignment_submissions sub
        JOIN students s ON s.id = sub.student_id
        WHERE sub.assignment_id = %s
        ORDER BY sub.submitted_at DESC
    """, (aid,))
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        for k, v in r.items():
            if hasattr(v, 'isoformat'):
                r[k] = str(v)
    return jsonify(rows)
@app.route("/api/branch-marks", methods=["GET"])
@login_required(roles=["faculty", "student"])
def branch_marks():
    dept    = (request.args.get("department") or "").strip()
    subject = (request.args.get("subject") or "").strip()

    if not dept or not subject:
        return jsonify({"error": "department and subject required"}), 400

    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT s.id, s.full_name, s.department,
               sm.subject, sm.marks,
               COALESCE(sm.internal_marks, 0) AS internal_marks,
               COALESCE(sm.external_marks, 0) AS external_marks
        FROM students s
        JOIN subject_marks sm ON sm.student_id = s.id
        WHERE s.department = %s AND sm.subject = %s
        ORDER BY sm.marks DESC
    """, (dept, subject))
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        for k, v in r.items():
            if hasattr(v, 'isoformat'): r[k] = str(v)
    return jsonify(rows)
@app.route("/api/students/export-high-performers", methods=["GET"])
@login_required(roles=["admin", "faculty"])
def export_high_performers():
    import csv, io
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT s.full_name, s.department, s.enrolled_at,
               ROUND(COALESCE(AVG(sm.marks), 0), 2) AS avg_marks
        FROM students s
        LEFT JOIN subject_marks sm ON sm.student_id = s.id
        GROUP BY s.id
    """)
    all_students = cur.fetchall(); cur.close(); conn.close()

    if not all_students:
        return jsonify({"error": "No students found"}), 404

    overall_avg = sum(float(s["avg_marks"]) for s in all_students) / len(all_students)
    high = [s for s in all_students if float(s["avg_marks"]) > overall_avg]
    high.sort(key=lambda s: float(s["avg_marks"]), reverse=True)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["full_name","department","enrolled_at","avg_marks"])
    writer.writeheader()
    writer.writerows(high)

    from flask import Response
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=high_performers_{timestamp}.csv"}
    )
@app.route("/api/users/check-username", methods=["GET"])
@login_required(roles=["admin", "faculty"])
def check_username():
    username = (request.args.get("username") or "").strip().lower()
    if not username:
        return jsonify({"available": False}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE LOWER(username)=%s", (username,))
    taken = cur.fetchone() is not None
    cur.close(); conn.close()
    return jsonify({"available": not taken})

if __name__ == "__main__":
    print("🚀 SPA Flask API running on http://localhost:5000")
    app.run(debug=True, port=5000)