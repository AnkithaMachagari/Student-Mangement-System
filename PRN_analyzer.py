import bcrypt
import mysql.connector
import getpass

# ── DB CONFIG ─────────────────────────────────────
DB_CONFIG = {
    "host":     "localhost",
    "user":     "root",          # change if needed
    "password": "",              # your MySQL root password
    "database": "spa_db",
}

def main():
    print("=== SPA Admin Seeder ===")
    username = input("Admin username [admin]: ").strip() or "admin"
    temp_pw  = getpass.getpass("Temp password for admin (they'll change on first login): ")
    if len(temp_pw) < 6:
        print("Password must be at least 6 characters.")
        return

    pwd_hash = bcrypt.hashpw(temp_pw.encode(), bcrypt.gensalt()).decode()

    conn = mysql.connector.connect(**DB_CONFIG)
    cur  = conn.cursor()

    # Check if admin already exists
    cur.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
    if cur.fetchone():
        print("Admin already exists. Skipping.")
        cur.close(); conn.close(); return

    cur.execute(
        "INSERT INTO users (username, pwd_hash, role, must_change_pwd) VALUES (%s, %s, 'admin', 1)",
        (username, pwd_hash)
    )
    conn.commit()
    print(f"✅  Admin '{username}' created. They must change password on first login.")
    cur.close(); conn.close()
    

if __name__ == "__main__":
    main()
