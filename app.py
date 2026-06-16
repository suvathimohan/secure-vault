# ============================================================
# SECURE FILE UPLOAD SYSTEM
# ============================================================
# INSTALLATION:
#   pip install flask pymysql werkzeug flask-wtf flask-limiter
#
# DATABASE SETUP:
#   CREATE DATABASE secure_upload_system;
#
# RUN:
#   python app.py
#
# DEFAULT ADMIN:
#   Email:    admin@system.com
#   Password: admin123
# ============================================================

import os
import re
import uuid
import hashlib
import mimetypes
from datetime import datetime, timedelta
from functools import wraps

import pymysql
from flask import (
    Flask, request, session, redirect, url_for,
    render_template_string, jsonify, send_from_directory, abort, g
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ─────────────────────────────────────────────
# APP CONFIGURATION
# ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(32).hex()
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per hour"],
    storage_uri="memory://"
)

# ─────────────────────────────────────────────
# DATABASE CONFIG
# ─────────────────────────────────────────────
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '123456789',
    'database': 'secure_upload_system',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

def get_db():
    if 'db' not in g:
        g.db = pymysql.connect(**DB_CONFIG)
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def query(sql, args=(), one=False, commit=False):
    db = get_db()
    with db.cursor() as cur:
        cur.execute(sql, args)
        if commit:
            db.commit()
            return cur.lastrowid
        rv = cur.fetchone() if one else cur.fetchall()
    return rv

# ─────────────────────────────────────────────
# DATABASE INITIALISATION
# ─────────────────────────────────────────────
def init_db():
    conn = pymysql.connect(
        host=DB_CONFIG['host'],
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        charset=DB_CONFIG['charset'],
        cursorclass=DB_CONFIG['cursorclass']
    )
    with conn.cursor() as cur:
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_CONFIG['database']}`")
        cur.execute(f"USE `{DB_CONFIG['database']}`")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(80) NOT NULL,
                email VARCHAR(120) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('admin','user') DEFAULT 'user',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active TINYINT(1) DEFAULT 1
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                original_name VARCHAR(255) NOT NULL,
                stored_name VARCHAR(255) NOT NULL,
                file_size BIGINT NOT NULL,
                mime_type VARCHAR(120),
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS malware_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                filename VARCHAR(255),
                reason TEXT,
                ip_address VARCHAR(45),
                detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                action VARCHAR(255),
                detail TEXT,
                ip_address VARCHAR(45),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        admin_hash = generate_password_hash('admin123')
        cur.execute("""
            INSERT IGNORE INTO users (username, email, password_hash, role)
            VALUES (%s, %s, %s, 'admin')
        """, ('Admin', 'admin@system.com', admin_hash))
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
# SECURITY HELPERS
# ─────────────────────────────────────────────
VIRUSTOTAL_API_KEY = 'b7cae64e927fd17179f434972f7aa0b1e8e8b1b5192958a121bc7575c02d98a6'

DANGEROUS_EXTENSIONS = {'.exe','.bat','.cmd','.vbs','.scr','.com','.pif',
                        '.msi','.ps1','.wsf','.hta','.reg'}
SUSPICIOUS_PATTERNS  = [r'\.\./', r'%00', r'<\?php']

def scan_file(filename, filepath):
    """Real VirusTotal scan + basic local checks. Returns (safe: bool, reason: str)."""
    import hashlib
    import time
    import json
    import requests as req_lib

    name_lower = filename.lower()
    _, ext = os.path.splitext(name_lower)

    # Step 1 — Local quick checks
    if ext in DANGEROUS_EXTENSIONS:
        return False, f"Dangerous file extension blocked: {ext}"
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, filename, re.IGNORECASE):
            return False, f"Suspicious filename pattern: {pat}"
    try:
        with open(filepath, 'rb') as fh:
            raw = fh.read()
        if raw[:2] == b'MZ':
            return False, "Executable binary (MZ header) detected"
    except Exception:
        return True, ""

    # Step 2 — Hash check (free, no quota used)
    try:
        file_hash = hashlib.sha256(raw).hexdigest()
        headers   = {"x-apikey": VIRUSTOTAL_API_KEY}

        r = req_lib.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers=headers, timeout=15
        )
        if r.status_code == 200:
            stats     = r.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious= stats.get('suspicious', 0)
            if malicious > 0 or suspicious > 2:
                engines     = r.json()['data']['attributes'].get('last_analysis_results', {})
                detected_by = [k for k,v in engines.items()
                               if v['category'] in ('malicious','suspicious')][:3]
                return False, f"VirusTotal: {malicious} engines detected malware. ({', '.join(detected_by)})"
            print(f"[VT] Hash known — clean ✅")
            return True, ""

        elif r.status_code == 404:
            # File not in VT db — upload for fresh scan
            print(f"[VT] Hash unknown, uploading for fresh scan...")
            upload = req_lib.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files={"file": (filename, raw, "application/octet-stream")},
                timeout=30
            )
            if upload.status_code != 200:
                print(f"[VT] Upload failed: {upload.status_code}")
                return True, ""

            analysis_id = upload.json()['data']['id']
            print(f"[VT] Uploaded, polling results...")

            # Step 3 — Poll up to 120 seconds (free account is slow)
            for i in range(12):
                time.sleep(10)
                poll = req_lib.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers, timeout=15
                )
                data   = poll.json()['data']['attributes']
                status = data['status']
                print(f"[VT] Poll {i+1}/12 — status: {status}")
                if status == 'completed':
                    stats     = data['stats']
                    malicious = stats.get('malicious', 0)
                    suspicious= stats.get('suspicious', 0)
                    if malicious > 0 or suspicious > 2:
                        engines     = data.get('results', {})
                        detected_by = [k for k,v in engines.items()
                                       if v['category'] in ('malicious','suspicious')][:3]
                        return False, f"VirusTotal: {malicious} engines detected malware. ({', '.join(detected_by)})"
                    print(f"[VT] Scan complete — clean ✅")
                    return True, ""

            print(f"[VT] Scan queued, allowing file")
            return True, ""
        else:
            print(f"[VT] API error: {r.status_code}")
            return True, ""

    except Exception as e:
        print(f"[VT ERROR] {e}")
        return True, ""

def log_activity(user_id, action, detail=""):
    try:
        ip = request.remote_addr
        query("INSERT INTO activity_logs (user_id, action, detail, ip_address) VALUES (%s,%s,%s,%s)",
              (user_id, action, detail, ip), commit=True)
    except Exception:
        pass

def log_malware(user_id, filename, reason):
    try:
        ip = request.remote_addr
        query("INSERT INTO malware_logs (user_id, filename, reason, ip_address) VALUES (%s,%s,%s,%s)",
              (user_id, filename, reason, ip), commit=True)
    except Exception:
        pass

# ─────────────────────────────────────────────
# AUTH DECORATORS
# ─────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
# HTML TEMPLATES (inline)
# ─────────────────────────────────────────────

BASE_STYLE = """
<style>
  @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:wght@400;500&display=swap');
  :root {
    --bg:       #0a0c10;
    --surface:  #111318;
    --surface2: #181c24;
    --border:   #242830;
    --accent:   #00e5ff;
    --accent2:  #7c3aed;
    --danger:   #ff3b6b;
    --success:  #00e096;
    --warning:  #ffb800;
    --text:     #e2e8f0;
    --muted:    #64748b;
    --font:     'Syne', sans-serif;
    --mono:     'DM Mono', monospace;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); min-height: 100vh; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* Sidebar */
  .sidebar {
    position: fixed; top: 0; left: 0; height: 100vh; width: 240px;
    background: var(--surface); border-right: 1px solid var(--border);
    display: flex; flex-direction: column; z-index: 100; transition: transform .3s;
  }
  .sidebar-logo {
    padding: 24px 20px 20px;
    font-size: 1.1rem; font-weight: 800; letter-spacing: -.5px;
    color: var(--accent); border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 10px;
  }
  .sidebar-logo svg { flex-shrink: 0; }
  .sidebar-nav { flex: 1; padding: 16px 0; overflow-y: auto; }
  .nav-section { padding: 8px 20px 4px; font-size: .65rem; font-weight: 700;
    letter-spacing: 1.5px; color: var(--muted); text-transform: uppercase; }
  .nav-item { display: flex; align-items: center; gap: 10px; padding: 10px 20px;
    color: var(--muted); font-size: .875rem; font-weight: 600; cursor: pointer;
    transition: all .2s; border-left: 3px solid transparent; text-decoration: none; }
  .nav-item:hover, .nav-item.active {
    color: var(--text); background: var(--surface2); border-left-color: var(--accent);
    text-decoration: none;
  }
  .nav-item svg { flex-shrink: 0; }
  .sidebar-footer { padding: 16px 20px; border-top: 1px solid var(--border);
    font-size: .8rem; color: var(--muted); }

  /* Main content */
  .main { margin-left: 240px; min-height: 100vh; }
  .topbar {
    background: var(--surface); border-bottom: 1px solid var(--border);
    padding: 0 28px; height: 60px; display: flex; align-items: center;
    justify-content: space-between; position: sticky; top: 0; z-index: 50;
  }
  .topbar-title { font-size: 1rem; font-weight: 700; }
  .topbar-right { display: flex; align-items: center; gap: 16px; }
  .user-badge {
    display: flex; align-items: center; gap: 8px; font-size: .8rem;
    background: var(--surface2); padding: 6px 12px; border-radius: 20px;
    border: 1px solid var(--border);
  }
  .role-tag {
    font-size: .65rem; padding: 2px 7px; border-radius: 8px; font-weight: 700;
    letter-spacing: .5px; text-transform: uppercase;
  }
  .role-tag.admin { background: #7c3aed33; color: var(--accent2); }
  .role-tag.user  { background: #00e5ff22; color: var(--accent); }
  .content { padding: 28px; }

  /* Cards */
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 20px;
  }
  .card-header { font-size: .95rem; font-weight: 700; margin-bottom: 16px;
    padding-bottom: 12px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 8px;
  }
  .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr)); gap: 16px; margin-bottom: 24px; }
  .stat-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 20px; display: flex; align-items: center; gap: 16px;
  }
  .stat-icon {
    width: 48px; height: 48px; border-radius: 12px; display: flex;
    align-items: center; justify-content: center; flex-shrink: 0;
  }
  .stat-icon.blue   { background: #00e5ff15; color: var(--accent); }
  .stat-icon.purple { background: #7c3aed20; color: var(--accent2); }
  .stat-icon.green  { background: #00e09620; color: var(--success); }
  .stat-icon.red    { background: #ff3b6b20; color: var(--danger); }
  .stat-label { font-size: .75rem; color: var(--muted); font-weight: 600;
    text-transform: uppercase; letter-spacing: .5px; }
  .stat-value { font-size: 1.75rem; font-weight: 800; line-height: 1.1; }

  /* Tables */
  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: .85rem; }
  thead th { padding: 10px 14px; text-align: left; font-size: .7rem; font-weight: 700;
    letter-spacing: .8px; text-transform: uppercase; color: var(--muted);
    border-bottom: 1px solid var(--border); }
  tbody td { padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover td { background: var(--surface2); }

  /* Buttons */
  .btn {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 8px 16px; border-radius: 8px; font-size: .82rem;
    font-weight: 700; font-family: var(--font); cursor: pointer;
    border: none; transition: all .2s; text-decoration: none;
  }
  .btn:hover { text-decoration: none; transform: translateY(-1px); }
  .btn-primary { background: var(--accent); color: #000; }
  .btn-primary:hover { background: #00cfeb; color: #000; }
  .btn-danger  { background: #ff3b6b22; color: var(--danger); border: 1px solid #ff3b6b44; }
  .btn-danger:hover  { background: var(--danger); color: #fff; }
  .btn-ghost   { background: var(--surface2); color: var(--text); border: 1px solid var(--border); }
  .btn-ghost:hover   { background: var(--border); }
  .btn-sm { padding: 5px 10px; font-size: .75rem; }
  .btn-success { background: #00e09620; color: var(--success); border: 1px solid #00e09644; }
  .btn-success:hover { background: var(--success); color: #000; }

  /* Forms */
  .form-group { margin-bottom: 18px; }
  .form-label { display: block; font-size: .8rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: .5px; color: var(--muted); margin-bottom: 6px; }
  .form-control {
    width: 100%; padding: 10px 14px; background: var(--surface2);
    border: 1px solid var(--border); border-radius: 8px; color: var(--text);
    font-family: var(--font); font-size: .9rem; transition: border-color .2s;
  }
  .form-control:focus { outline: none; border-color: var(--accent); }

  /* Badges */
  .badge { display: inline-block; padding: 2px 8px; border-radius: 6px;
    font-size: .7rem; font-weight: 700; text-transform: uppercase; letter-spacing: .5px; }
  .badge-success { background: #00e09622; color: var(--success); }
  .badge-danger  { background: #ff3b6b22; color: var(--danger); }
  .badge-warning { background: #ffb80022; color: var(--warning); }
  .badge-info    { background: #00e5ff15; color: var(--accent); }

  /* Alerts */
  .alert { padding: 12px 16px; border-radius: 8px; font-size: .875rem; margin-bottom: 16px; }
  .alert-danger  { background: #ff3b6b15; border: 1px solid #ff3b6b44; color: var(--danger); }
  .alert-success { background: #00e09615; border: 1px solid #00e09644; color: var(--success); }
  .alert-warning { background: #ffb80015; border: 1px solid #ffb80044; color: var(--warning); }

  /* Upload zone */
  .drop-zone {
    border: 2px dashed var(--border); border-radius: 12px; padding: 48px 24px;
    text-align: center; cursor: pointer; transition: all .2s; position: relative;
  }
  .drop-zone:hover, .drop-zone.drag-over {
    border-color: var(--accent); background: #00e5ff08;
  }
  .drop-zone-icon { font-size: 3rem; margin-bottom: 12px; }
  .drop-zone-text { font-size: 1rem; font-weight: 600; margin-bottom: 4px; }
  .drop-zone-sub  { font-size: .82rem; color: var(--muted); }
  #fileInput { position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%; height: 100%; }

  /* Progress */
  .progress-bar-wrap { background: var(--surface2); border-radius: 8px; height: 8px;
    overflow: hidden; margin: 8px 0; }
  .progress-bar { height: 100%; background: linear-gradient(90deg, var(--accent), var(--accent2));
    transition: width .3s; border-radius: 8px; }

  /* Modal */
  .modal-overlay {
    position: fixed; inset: 0; background: #000a; z-index: 999;
    display: flex; align-items: center; justify-content: center;
    opacity: 0; pointer-events: none; transition: opacity .2s;
  }
  .modal-overlay.show { opacity: 1; pointer-events: all; }
  .modal-box {
    background: var(--surface); border: 1px solid var(--border); border-radius: 16px;
    padding: 28px; max-width: 440px; width: 90%; position: relative;
    transform: scale(.95); transition: transform .2s;
  }
  .modal-overlay.show .modal-box { transform: scale(1); }
  .modal-title { font-size: 1.1rem; font-weight: 800; margin-bottom: 12px; color: var(--danger); }
  .modal-body  { font-size: .875rem; color: var(--muted); line-height: 1.6; }
  .modal-footer { margin-top: 20px; display: flex; justify-content: flex-end; gap: 10px; }

  /* Auth pages */
  .auth-wrap {
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: var(--bg);
    background-image: radial-gradient(ellipse at 20% 50%, #7c3aed18 0%, transparent 60%),
                      radial-gradient(ellipse at 80% 20%, #00e5ff12 0%, transparent 50%);
  }
  .auth-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 16px;
    padding: 36px; width: 100%; max-width: 400px;
  }
  .auth-logo { text-align: center; margin-bottom: 28px; }
  .auth-logo-icon { font-size: 2.2rem; margin-bottom: 8px; }
  .auth-logo h1 { font-size: 1.5rem; font-weight: 800; color: var(--accent); }
  .auth-logo p  { font-size: .82rem; color: var(--muted); margin-top: 4px; }
  .auth-divider { text-align: center; margin: 16px 0; color: var(--muted); font-size: .8rem; position: relative; }
  .auth-divider::before, .auth-divider::after {
    content: ''; position: absolute; top: 50%; width: 40%; height: 1px; background: var(--border);
  }
  .auth-divider::before { left: 0; }
  .auth-divider::after  { right: 0; }

  /* Responsive */
  @media (max-width: 768px) {
    .sidebar { transform: translateX(-100%); }
    .sidebar.open { transform: translateX(0); }
    .main { margin-left: 0; }
    .topbar { padding: 0 16px; }
    .content { padding: 16px; }
    .stat-grid { grid-template-columns: 1fr 1fr; }
  }

  .hamburger { display: none; cursor: pointer; }
  @media (max-width: 768px) { .hamburger { display: flex; } }

  .file-size { font-family: var(--mono); font-size: .78rem; color: var(--muted); }
  .empty-state { text-align: center; padding: 48px; color: var(--muted); }
  .empty-state svg { margin-bottom: 12px; opacity: .4; }

  .scan-item { background: var(--surface2); border-radius: 8px; padding: 8px 12px;
    margin: 4px 0; display: flex; align-items: center; gap: 8px; font-size: .82rem; }
  .scan-item.ok   { border-left: 3px solid var(--success); }
  .scan-item.fail { border-left: 3px solid var(--danger); }

  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 900px) { .grid-2 { grid-template-columns: 1fr; } }
</style>
"""

def sidebar_html(active='dashboard'):
    role = session.get('role', 'user')
    admin_items = ''
    if role == 'admin':
        admin_items = f"""
        <div class="nav-section">Admin</div>
        <a href="/admin" class="nav-item {'active' if active=='admin' else ''}">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
          Admin Panel
        </a>
        <a href="/admin/users" class="nav-item {'active' if active=='users' else ''}">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
          Users
        </a>
        <a href="/admin/malware" class="nav-item {'active' if active=='malware' else ''}">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Malware Logs
        </a>
        <a href="/admin/activity" class="nav-item {'active' if active=='activity' else ''}">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          Activity Logs
        </a>
        """
    return f"""
    <div class="sidebar" id="sidebar">
      <div class="sidebar-logo">
        <svg width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        SecureVault
      </div>
      <nav class="sidebar-nav">
        <div class="nav-section">Main</div>
        <a href="/dashboard" class="nav-item {'active' if active=='dashboard' else ''}">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          Dashboard
        </a>
        <a href="/upload" class="nav-item {'active' if active=='upload' else ''}">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
          Upload Files
        </a>
        <a href="/files" class="nav-item {'active' if active=='files' else ''}">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
          My Files
        </a>
        {admin_items}
      </nav>
      <div class="sidebar-footer">
        <div style="margin-bottom:8px;font-size:.82rem;font-weight:600;">{session.get('username','')}</div>
        <a href="/logout" class="btn btn-ghost btn-sm" style="width:100%;justify-content:center;">
          <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
          Logout
        </a>
      </div>
    </div>
    """

def layout(content, title="Dashboard", active='dashboard'):
    return render_template_string("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{ title }} — SecureVault</title>
""" + BASE_STYLE + """
</head>
<body>
""" + sidebar_html(active) + """
<div class="main" id="main">
  <div class="topbar">
    <div style="display:flex;align-items:center;gap:12px;">
      <button class="hamburger btn btn-ghost btn-sm" onclick="toggleSidebar()">
        <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>
        </svg>
      </button>
      <span class="topbar-title">{{ title }}</span>
    </div>
    <div class="topbar-right">
      <div class="user-badge">
        <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        {{ session.get('username') }}
        <span class="role-tag {{ session.get('role','user') }}">{{ session.get('role','user') }}</span>
      </div>
    </div>
  </div>
  <div class="content">
""" + content + """
  </div>
</div>
<script>
function toggleSidebar(){
  document.getElementById('sidebar').classList.toggle('open');
}
document.addEventListener('click', function(e){
  const sb = document.getElementById('sidebar');
  const hb = document.querySelector('.hamburger');
  if(window.innerWidth <= 768 && !sb.contains(e.target) && hb && !hb.contains(e.target)){
    sb.classList.remove('open');
  }
});
</script>
</body>
</html>""", title=title, session=session)

# ─────────────────────────────────────────────
# ROUTES — AUTH
# ─────────────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
@limiter.limit("20 per minute")
def login():
    error = ''
    if request.method == 'POST':
        email    = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        user = query("SELECT * FROM users WHERE email=%s AND is_active=1", (email,), one=True)
        if user and check_password_hash(user['password_hash'], password):
            session.permanent = True
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['role']     = user['role']
            log_activity(user['id'], 'LOGIN', f"from {request.remote_addr}")
            return redirect(url_for('dashboard'))
        error = 'Invalid email or password.'

    html = f"""
    <div class="auth-wrap">
      <div class="auth-card">
        <div class="auth-logo">
          <div class="auth-logo-icon">🔐</div>
          <h1>SecureVault</h1>
          <p>Secure File Upload System</p>
        </div>
        {'<div class="alert alert-danger">'+error+'</div>' if error else ''}
        <form method="POST">
          <input type="hidden" name="csrf_token" value="{{{{ csrf_token() }}}}">
          <div class="form-group">
            <label class="form-label">Email Address</label>
            <input class="form-control" type="email" name="email" required placeholder="you@example.com"/>
          </div>
          <div class="form-group">
            <label class="form-label">Password</label>
            <input class="form-control" type="password" name="password" required placeholder="••••••••"/>
          </div>
          <button class="btn btn-primary" style="width:100%;justify-content:center;" type="submit">Sign In</button>
        </form>
        <div class="auth-divider">or</div>
        <div style="text-align:center;font-size:.85rem;color:var(--muted);">
          Don't have an account? <a href="/register">Register</a>
        </div>
      </div>
    </div>
    """
    return render_template_string("<!DOCTYPE html><html><head><meta charset='UTF-8'/><meta name='viewport' content='width=device-width,initial-scale=1'/><title>Login — SecureVault</title>" + BASE_STYLE + "</head><body>" + html + "</body></html>")

@app.route('/register', methods=['GET','POST'])
@limiter.limit("10 per hour")
def register():
    error = ''
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        email    = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        confirm  = request.form.get('confirm','')
        if not username or not email or not password:
            error = 'All fields are required.'
        elif password != confirm:
            error = 'Passwords do not match.'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters.'
        elif query("SELECT id FROM users WHERE email=%s", (email,), one=True):
            error = 'Email already registered.'
        else:
            pw_hash = generate_password_hash(password)
            query("INSERT INTO users (username,email,password_hash) VALUES (%s,%s,%s)",
                  (username, email, pw_hash), commit=True)
            return redirect(url_for('login'))

    html = f"""
    <div class="auth-wrap">
      <div class="auth-card">
        <div class="auth-logo">
          <div class="auth-logo-icon">🔐</div>
          <h1>SecureVault</h1>
          <p>Create your account</p>
        </div>
        {'<div class="alert alert-danger">'+error+'</div>' if error else ''}
        <form method="POST">
          <input type="hidden" name="csrf_token" value="{{{{ csrf_token() }}}}">
          <div class="form-group">
            <label class="form-label">Username</label>
            <input class="form-control" type="text" name="username" required placeholder="johndoe"/>
          </div>
          <div class="form-group">
            <label class="form-label">Email Address</label>
            <input class="form-control" type="email" name="email" required placeholder="you@example.com"/>
          </div>
          <div class="form-group">
            <label class="form-label">Password</label>
            <input class="form-control" type="password" name="password" required placeholder="••••••••"/>
          </div>
          <div class="form-group">
            <label class="form-label">Confirm Password</label>
            <input class="form-control" type="password" name="confirm" required placeholder="••••••••"/>
          </div>
          <button class="btn btn-primary" style="width:100%;justify-content:center;" type="submit">Create Account</button>
        </form>
        <div class="auth-divider">or</div>
        <div style="text-align:center;font-size:.85rem;color:var(--muted);">
          Already have an account? <a href="/login">Sign In</a>
        </div>
      </div>
    </div>
    """
    return render_template_string("<!DOCTYPE html><html><head><meta charset='UTF-8'/><meta name='viewport' content='width=device-width,initial-scale=1'/><title>Register — SecureVault</title>" + BASE_STYLE + "</head><body>" + html + "</body></html>")

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], 'LOGOUT')
    session.clear()
    return redirect(url_for('login'))

# ─────────────────────────────────────────────
# ROUTES — DASHBOARD
# ─────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    uid  = session['user_id']
    role = session.get('role')

    my_files  = query("SELECT COUNT(*) as c FROM files WHERE user_id=%s", (uid,), one=True)['c']
    my_size_r = query("SELECT SUM(file_size) as s FROM files WHERE user_id=%s", (uid,), one=True)
    my_size   = my_size_r['s'] or 0

    malware_threats = query("SELECT COUNT(*) as c FROM malware_logs WHERE user_id=%s", (uid,), one=True)['c']
    recent_files = query("SELECT * FROM files WHERE user_id=%s ORDER BY uploaded_at DESC LIMIT 5", (uid,))

    total_users = total_files = total_malware = 0
    if role == 'admin':
        total_users  = query("SELECT COUNT(*) as c FROM users", one=True)['c']
        total_files  = query("SELECT COUNT(*) as c FROM files", one=True)['c']
        total_malware= query("SELECT COUNT(*) as c FROM malware_logs", one=True)['c']

    def fmt_size(b):
        for u in ['B','KB','MB','GB']:
            if b < 1024: return f"{b:.1f} {u}"
            b /= 1024
        return f"{b:.1f} TB"

    admin_stats = ''
    if role == 'admin':
        admin_stats = f"""
        <div class="stat-card">
          <div class="stat-icon purple">
            <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
          </div>
          <div><div class="stat-label">Total Users</div><div class="stat-value">{total_users}</div></div>
        </div>
        <div class="stat-card">
          <div class="stat-icon blue">
            <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
          </div>
          <div><div class="stat-label">All Files</div><div class="stat-value">{total_files}</div></div>
        </div>
        <div class="stat-card">
          <div class="stat-icon red">
            <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </div>
          <div><div class="stat-label">Threats Detected</div><div class="stat-value">{total_malware}</div></div>
        </div>
        """

    rows = ''
    for f in recent_files:
        rows += f"""
        <tr>
          <td>{f['original_name']}</td>
          <td class="file-size">{fmt_size(f['file_size'])}</td>
          <td><span class="badge badge-info">{f['mime_type'] or 'unknown'}</span></td>
          <td class="file-size">{f['uploaded_at'].strftime('%Y-%m-%d %H:%M')}</td>
          <td>
            <a href="/download/{f['id']}" class="btn btn-success btn-sm">↓</a>
            <a href="/delete/{f['id']}" class="btn btn-danger btn-sm" onclick="return confirm('Delete this file?')">✕</a>
          </td>
        </tr>
        """
    if not rows:
        rows = '<tr><td colspan="5"><div class="empty-state">No files uploaded yet</div></td></tr>'

    content = f"""
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-icon green">
          <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        </div>
        <div><div class="stat-label">My Files</div><div class="stat-value">{my_files}</div></div>
      </div>
      <div class="stat-card">
        <div class="stat-icon blue">
          <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        </div>
        <div><div class="stat-label">Storage Used</div><div class="stat-value">{fmt_size(my_size)}</div></div>
      </div>
      <div class="stat-card">
        <div class="stat-icon red">
          <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <div><div class="stat-label">Threats Blocked</div><div class="stat-value">{malware_threats}</div></div>
      </div>
      {admin_stats}
    </div>

    <div class="card">
      <div class="card-header">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg>
        Recent Uploads
        <a href="/upload" class="btn btn-primary btn-sm" style="margin-left:auto;">Upload New</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Size</th><th>Type</th><th>Uploaded</th><th>Actions</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>
    """
    return layout(content, "Dashboard", "dashboard")

# ─────────────────────────────────────────────
# ROUTES — UPLOAD
# ─────────────────────────────────────────────
@app.route('/upload', methods=['GET','POST'])
@login_required
@limiter.limit("60 per hour")
@csrf.exempt
def upload():
    results = []
    if request.method == 'POST':
        files = request.files.getlist('files')
        for f in files:
            if not f or not f.filename:
                continue
            original = f.filename
            safe     = secure_filename(original)
            if not safe:
                results.append({'name': original, 'ok': False, 'msg': 'Invalid filename'})
                continue

            # Save temp to scan
            tmp_name = str(uuid.uuid4()) + '_' + safe
            tmp_path = os.path.join(UPLOAD_FOLDER, tmp_name)
            f.save(tmp_path)

            safe_flag, reason = scan_file(original, tmp_path)
            if not safe_flag:
                os.remove(tmp_path)
                log_malware(session['user_id'], original, reason)
                results.append({'name': original, 'ok': False, 'msg': f'⚠ Threat detected: {reason}'})
                log_activity(session['user_id'], 'MALWARE_BLOCKED', f"{original} — {reason}")
                continue

            size = os.path.getsize(tmp_path)
            mime = mimetypes.guess_type(original)[0] or 'application/octet-stream'
            query("INSERT INTO files (user_id,original_name,stored_name,file_size,mime_type) VALUES (%s,%s,%s,%s,%s)",
                  (session['user_id'], original, tmp_name, size, mime), commit=True)
            results.append({'name': original, 'ok': True, 'msg': 'Uploaded successfully'})
            log_activity(session['user_id'], 'FILE_UPLOAD', original)

        return jsonify(results)

    content = """
    <div class="card" style="max-width:700px;margin:0 auto;">
      <div class="card-header">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
        Upload Files
      </div>

      <div class="drop-zone" id="dropZone">
        <input type="file" id="fileInput" multiple/>
        <div class="drop-zone-icon">📁</div>
        <div class="drop-zone-text">Drag &amp; drop files here</div>
        <div class="drop-zone-sub">or click to browse — max 50 MB per file</div>
      </div>

      <div id="scanResults" style="margin-top:16px;display:none;">
        <div class="card-header" style="font-size:.82rem;">Scan Results</div>
        <div id="scanList"></div>
      </div>

      <div id="progressWrap" style="display:none;margin-top:16px;">
        <div style="font-size:.82rem;color:var(--muted);margin-bottom:6px;">Uploading & scanning...</div>
        <div class="progress-bar-wrap"><div class="progress-bar" id="progressBar" style="width:0%"></div></div>
        <div id="progressLabel" style="font-size:.75rem;color:var(--muted);margin-top:4px;font-family:var(--mono);">0%</div>
      </div>

      <div style="margin-top:16px;font-size:.78rem;color:var(--muted);">
        🛡 Files are automatically scanned for malware &amp; threats before storage.
      </div>
    </div>

    <!-- Malware Modal -->
    <div class="modal-overlay" id="malwareModal">
      <div class="modal-box">
        <div class="modal-title">⚠ Threat Detected!</div>
        <div class="modal-body" id="malwareModalBody"></div>
        <div class="modal-footer">
          <button class="btn btn-danger" onclick="document.getElementById('malwareModal').classList.remove('show')">Dismiss</button>
        </div>
      </div>
    </div>

    <script>
    const dropZone  = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');

    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone.addEventListener('drop', e => {
      e.preventDefault(); dropZone.classList.remove('drag-over');
      uploadFiles(e.dataTransfer.files);
    });
    fileInput.addEventListener('change', () => uploadFiles(fileInput.files));

    function uploadFiles(files) {
      if (!files.length) return;
      const fd = new FormData();
      for (const f of files) fd.append('files', f);

      const progressWrap = document.getElementById('progressWrap');
      const progressBar  = document.getElementById('progressBar');
      const progressLabel= document.getElementById('progressLabel');
      const scanResults  = document.getElementById('scanResults');
      const scanList     = document.getElementById('scanList');

      progressWrap.style.display = 'block';
      scanResults.style.display  = 'none';
      scanList.innerHTML = '';

      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/upload');
      xhr.upload.onprogress = e => {
        if (e.lengthComputable) {
          const pct = Math.round(e.loaded / e.total * 100);
          progressBar.style.width = pct + '%';
          progressLabel.textContent = pct + '%';
        }
      };
      xhr.onload = () => {
        progressBar.style.width = '100%';
        progressLabel.textContent = '100%';
        try {
          const results = JSON.parse(xhr.responseText);
          scanResults.style.display = 'block';
          let hasThreats = false; let threatMsgs = [];
          results.forEach(r => {
            const el = document.createElement('div');
            el.className = 'scan-item ' + (r.ok ? 'ok' : 'fail');
            el.innerHTML = (r.ok ? '✅' : '🚫') + ' <strong>' + escapeHtml(r.name) + '</strong> — ' + escapeHtml(r.msg);
            scanList.appendChild(el);
            if (!r.ok) { hasThreats = true; threatMsgs.push(r.name + ': ' + r.msg); }
          });
          if (hasThreats) {
            document.getElementById('malwareModalBody').innerHTML =
              '<p>The following files were blocked:</p><ul style="margin-top:8px;padding-left:20px;">' +
              threatMsgs.map(m => '<li style="margin-top:4px;">'+escapeHtml(m)+'</li>').join('') + '</ul>';
            document.getElementById('malwareModal').classList.add('show');
          }
        } catch(e) {}
        setTimeout(() => { progressWrap.style.display = 'none'; }, 1500);
        fileInput.value = '';
      };
      xhr.onerror = () => { progressLabel.textContent = 'Upload failed'; };
      xhr.send(fd);
    }

    function escapeHtml(s) {
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
    </script>
    """
    return layout(content, "Upload Files", "upload")

# ─────────────────────────────────────────────
# ROUTES — MY FILES
# ─────────────────────────────────────────────
@app.route('/files')
@login_required
def my_files():
    uid   = session['user_id']
    files = query("SELECT * FROM files WHERE user_id=%s ORDER BY uploaded_at DESC", (uid,))

    def fmt_size(b):
        for u in ['B','KB','MB','GB']:
            if b < 1024: return f"{b:.1f} {u}"
            b /= 1024
        return f"{b:.1f} TB"

    rows = ''
    for f in files:
        rows += f"""
        <tr>
          <td>
            <div style="font-weight:600;font-size:.875rem;">{f['original_name']}</div>
            <div class="file-size">{f['stored_name']}</div>
          </td>
          <td class="file-size">{fmt_size(f['file_size'])}</td>
          <td><span class="badge badge-info">{f['mime_type'] or 'unknown'}</span></td>
          <td class="file-size">{f['uploaded_at'].strftime('%Y-%m-%d %H:%M')}</td>
          <td>
            <a href="/download/{f['id']}" class="btn btn-success btn-sm">↓ Download</a>
            <a href="/delete/{f['id']}" class="btn btn-danger btn-sm" onclick="return confirm('Delete this file?')">✕</a>
          </td>
        </tr>
        """
    if not rows:
        rows = '<tr><td colspan="5"><div class="empty-state"><svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg><p>No files yet. <a href="/upload">Upload something!</a></p></div></td></tr>'

    content = f"""
    <div class="card">
      <div class="card-header">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg>
        My Files ({len(files)})
        <a href="/upload" class="btn btn-primary btn-sm" style="margin-left:auto;">+ Upload</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>File</th><th>Size</th><th>Type</th><th>Uploaded</th><th>Actions</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>
    """
    return layout(content, "My Files", "files")

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    uid  = session['user_id']
    role = session.get('role')
    if role == 'admin':
        f = query("SELECT * FROM files WHERE id=%s", (file_id,), one=True)
    else:
        f = query("SELECT * FROM files WHERE id=%s AND user_id=%s", (file_id, uid), one=True)
    if not f:
        abort(404)
    log_activity(uid, 'FILE_DOWNLOAD', f['original_name'])
    return send_from_directory(UPLOAD_FOLDER, f['stored_name'], as_attachment=True, download_name=f['original_name'])

@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    uid  = session['user_id']
    role = session.get('role')
    if role == 'admin':
        f = query("SELECT * FROM files WHERE id=%s", (file_id,), one=True)
    else:
        f = query("SELECT * FROM files WHERE id=%s AND user_id=%s", (file_id, uid), one=True)
    if not f:
        abort(404)
    try:
        fp = os.path.join(UPLOAD_FOLDER, f['stored_name'])
        if os.path.exists(fp):
            os.remove(fp)
    except Exception:
        pass
    query("DELETE FROM files WHERE id=%s", (file_id,), commit=True)
    log_activity(uid, 'FILE_DELETE', f['original_name'])
    return redirect(request.referrer or url_for('my_files'))

# ─────────────────────────────────────────────
# ROUTES — ADMIN
# ─────────────────────────────────────────────
@app.route('/admin')
@admin_required
def admin_panel():
    total_users   = query("SELECT COUNT(*) as c FROM users", one=True)['c']
    total_files   = query("SELECT COUNT(*) as c FROM files", one=True)['c']
    total_malware = query("SELECT COUNT(*) as c FROM malware_logs", one=True)['c']
    total_size_r  = query("SELECT SUM(file_size) as s FROM files", one=True)
    total_size    = total_size_r['s'] or 0

    def fmt_size(b):
        for u in ['B','KB','MB','GB']:
            if b < 1024: return f"{b:.1f} {u}"
            b /= 1024
        return f"{b:.1f} TB"

    recent_activity = query("SELECT a.*, u.username FROM activity_logs a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.created_at DESC LIMIT 15")
    rows = ''
    for a in recent_activity:
        rows += f"""
        <tr>
          <td><span class="badge badge-info">{a['username'] or 'system'}</span></td>
          <td><span class="badge badge-warning">{a['action']}</span></td>
          <td style="font-size:.8rem;color:var(--muted);">{a['detail'] or ''}</td>
          <td class="file-size">{a['ip_address'] or ''}</td>
          <td class="file-size">{a['created_at'].strftime('%m-%d %H:%M')}</td>
        </tr>
        """
    if not rows:
        rows = '<tr><td colspan="5"><div class="empty-state">No activity yet</div></td></tr>'

    content = f"""
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-icon purple"><svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg></div>
        <div><div class="stat-label">Total Users</div><div class="stat-value">{total_users}</div></div>
      </div>
      <div class="stat-card">
        <div class="stat-icon blue"><svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg></div>
        <div><div class="stat-label">Total Files</div><div class="stat-value">{total_files}</div></div>
      </div>
      <div class="stat-card">
        <div class="stat-icon green"><svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div>
        <div><div class="stat-label">Storage Used</div><div class="stat-value">{fmt_size(total_size)}</div></div>
      </div>
      <div class="stat-card">
        <div class="stat-icon red"><svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
        <div><div class="stat-label">Threats Detected</div><div class="stat-value">{total_malware}</div></div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-header">Quick Actions</div>
        <div style="display:flex;flex-direction:column;gap:10px;">
          <a href="/admin/users"   class="btn btn-ghost">👥 Manage Users</a>
          <a href="/admin/malware" class="btn btn-ghost">🛡 Malware Logs</a>
          <a href="/admin/activity" class="btn btn-ghost">📋 Activity Logs</a>
        </div>
      </div>
      <div class="card">
        <div class="card-header">Recent Activity</div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>User</th><th>Action</th><th>Detail</th><th>IP</th><th>Time</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
      </div>
    </div>
    """
    return layout(content, "Admin Panel", "admin")

@app.route('/admin/users')
@admin_required
def admin_users():
    users = query("SELECT u.*, (SELECT COUNT(*) FROM files WHERE user_id=u.id) as file_count FROM users u ORDER BY u.created_at DESC")
    rows = ''
    for u in users:
        rows += f"""
        <tr>
          <td><span style="font-weight:600;">{u['username']}</span></td>
          <td style="font-size:.82rem;">{u['email']}</td>
          <td><span class="role-tag {u['role']}">{u['role']}</span></td>
          <td class="file-size">{u['file_count']}</td>
          <td class="file-size">{u['created_at'].strftime('%Y-%m-%d')}</td>
          <td><span class="badge {'badge-success' if u['is_active'] else 'badge-danger'}">{('Active' if u['is_active'] else 'Disabled')}</span></td>
          <td>
            {'<a href="/admin/delete_user/'+str(u['id'])+'" class="btn btn-danger btn-sm" onclick="return confirm(\'Delete user and all their files?\')">Delete</a>' if u['id'] != session['user_id'] else '<span style="color:var(--muted);font-size:.75rem;">current</span>'}
          </td>
        </tr>
        """
    if not rows:
        rows = '<tr><td colspan="7"><div class="empty-state">No users</div></td></tr>'

    content = f"""
    <div class="card">
      <div class="card-header">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>
        All Users ({len(users)})
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Files</th><th>Joined</th><th>Status</th><th>Action</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>
    """
    return layout(content, "User Management", "users")

@app.route('/admin/delete_user/<int:uid>')
@admin_required
def admin_delete_user(uid):
    if uid == session['user_id']:
        return redirect(url_for('admin_users'))
    # Delete physical files
    user_files = query("SELECT stored_name FROM files WHERE user_id=%s", (uid,))
    for f in user_files:
        fp = os.path.join(UPLOAD_FOLDER, f['stored_name'])
        if os.path.exists(fp):
            try: os.remove(fp)
            except: pass
    query("DELETE FROM users WHERE id=%s", (uid,), commit=True)
    log_activity(session['user_id'], 'DELETE_USER', str(uid))
    return redirect(url_for('admin_users'))

@app.route('/admin/malware')
@admin_required
def admin_malware():
    logs = query("SELECT m.*, u.username FROM malware_logs m LEFT JOIN users u ON m.user_id=u.id ORDER BY m.detected_at DESC")
    rows = ''
    for m in logs:
        rows += f"""
        <tr>
          <td><span class="badge badge-danger">THREAT</span></td>
          <td style="font-size:.875rem;font-weight:600;">{m['filename']}</td>
          <td style="font-size:.8rem;">{m['reason']}</td>
          <td><span class="badge badge-info">{m['username'] or 'unknown'}</span></td>
          <td class="file-size">{m['ip_address'] or ''}</td>
          <td class="file-size">{m['detected_at'].strftime('%Y-%m-%d %H:%M')}</td>
        </tr>
        """
    if not rows:
        rows = '<tr><td colspan="6"><div class="empty-state">No malware detected 🎉</div></td></tr>'

    content = f"""
    <div class="card">
      <div class="card-header" style="color:var(--danger);">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Malware Detection Log ({len(logs)} threats)
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Status</th><th>Filename</th><th>Reason</th><th>User</th><th>IP</th><th>Detected</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>
    """
    return layout(content, "Malware Logs", "malware")

@app.route('/admin/activity')
@admin_required
def admin_activity():
    logs = query("SELECT a.*, u.username FROM activity_logs a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.created_at DESC LIMIT 200")
    rows = ''
    action_colors = {
        'LOGIN': 'badge-success', 'LOGOUT': 'badge-info',
        'FILE_UPLOAD': 'badge-info', 'FILE_DOWNLOAD': 'badge-warning',
        'FILE_DELETE': 'badge-danger', 'MALWARE_BLOCKED': 'badge-danger',
        'DELETE_USER': 'badge-danger'
    }
    for a in logs:
        color = action_colors.get(a['action'], 'badge-info')
        rows += f"""
        <tr>
          <td><span class="badge badge-info">{a['username'] or 'system'}</span></td>
          <td><span class="badge {color}">{a['action']}</span></td>
          <td style="font-size:.8rem;color:var(--muted);">{a['detail'] or ''}</td>
          <td class="file-size">{a['ip_address'] or ''}</td>
          <td class="file-size">{a['created_at'].strftime('%Y-%m-%d %H:%M:%S')}</td>
        </tr>
        """
    if not rows:
        rows = '<tr><td colspan="5"><div class="empty-state">No activity yet</div></td></tr>'

    content = f"""
    <div class="card">
      <div class="card-header">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        Activity Logs ({len(logs)} entries)
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>User</th><th>Action</th><th>Detail</th><th>IP</th><th>Time</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>
    """
    return layout(content, "Activity Logs", "activity")

# ─────────────────────────────────────────────
# ERROR HANDLERS
# ─────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e):
    html = '<div class="auth-wrap"><div class="auth-card" style="text-align:center;"><div style="font-size:3rem;">🚫</div><h2 style="margin:12px 0 8px;">Access Denied</h2><p style="color:var(--muted);">You do not have permission to view this page.</p><a href="/dashboard" class="btn btn-primary" style="margin-top:16px;">Back to Dashboard</a></div></div>'
    return render_template_string("<!DOCTYPE html><html><head><meta charset='UTF-8'/><title>403</title>" + BASE_STYLE + "</head><body>" + html + "</body></html>"), 403

@app.errorhandler(404)
def not_found(e):
    html = '<div class="auth-wrap"><div class="auth-card" style="text-align:center;"><div style="font-size:3rem;">🔍</div><h2 style="margin:12px 0 8px;">Page Not Found</h2><p style="color:var(--muted);">The resource you requested does not exist.</p><a href="/dashboard" class="btn btn-primary" style="margin-top:16px;">Back to Dashboard</a></div></div>'
    return render_template_string("<!DOCTYPE html><html><head><meta charset='UTF-8'/><title>404</title>" + BASE_STYLE + "</head><body>" + html + "</body></html>"), 404

@app.errorhandler(429)
def rate_limited(e):
    html = '<div class="auth-wrap"><div class="auth-card" style="text-align:center;"><div style="font-size:3rem;">⏳</div><h2 style="margin:12px 0 8px;">Rate Limited</h2><p style="color:var(--muted);">Too many requests. Please slow down.</p><a href="/dashboard" class="btn btn-primary" style="margin-top:16px;">Back to Dashboard</a></div></div>'
    return render_template_string("<!DOCTYPE html><html><head><meta charset='UTF-8'/><title>429</title>" + BASE_STYLE + "</head><body>" + html + "</body></html>"), 429

# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == '__main__':
    print("="*55)
    print("  SecureVault — Secure File Upload System")
    print("="*55)
    print("  Initialising database...")
    init_db()
    print("  ✓ Database ready")
    print(f"  ✓ Upload folder: {UPLOAD_FOLDER}")
    print("  ✓ CSRF protection enabled")
    print("  ✓ Rate limiting enabled")
    print()
    print("  Default Admin Credentials:")
    print("    Email:    admin@system.com")
    print("    Password: admin123")
    print()
    print("  Server running at: http://127.0.0.1:5000")
    print("="*55)
    app.run(debug=True, host='0.0.0.0', port=5000)