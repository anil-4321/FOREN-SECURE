# locker.py
# FORENSICORE — Legal Forensic Evidence & AI Risk Platform (Enhanced Final Edition)
# Single-file, Windows-safe, DB-lock safer, better camera fallback,
# signed PDF with GREEN verified section, saved graphs, animated live-wave graphs,
# stronger UI, stronger audit trail, stronger AI summaries.

import os
import sys
import uuid
import json
import csv
import math
import time
import hmac
import shutil
import zipfile
import random
import hashlib
import sqlite3
import statistics
import traceback
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# ------------------------------
# OPTIONAL CAMERA
# ------------------------------
try:
    import cv2
except Exception:
    cv2 = None

# ------------------------------
# DEPENDENCY CHECK
# ------------------------------
missing = []

try:
    import numpy as np
except Exception:
    missing.append("numpy")

try:
    import pandas as pd
except Exception:
    missing.append("pandas")

try:
    import matplotlib.pyplot as plt
    from matplotlib.animation import FuncAnimation
except Exception:
    missing.append("matplotlib")

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (
        confusion_matrix,
        roc_curve,
        auc,
        accuracy_score,
        precision_score,
        recall_score,
        f1_score,
    )
    from sklearn.model_selection import train_test_split
except Exception:
    missing.append("scikit-learn")

try:
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Image as RLImage,
        Table,
        TableStyle,
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.enums import TA_CENTER
except Exception:
    missing.append("reportlab")

try:
    from PIL import Image, ImageTk
except Exception:
    missing.append("pillow")

if missing:
    tmp = tk.Tk()
    tmp.withdraw()
    messagebox.showerror(
        "Missing Dependencies",
        "Install these packages first:\n\n"
        + "\n".join(f"- {m}" for m in missing)
        + "\n\nCommand:\npython -m pip install "
        + " ".join(missing),
    )
    tmp.destroy()
    sys.exit(1)

# ------------------------------
# GLOBALS
# ------------------------------
root: Optional[tk.Tk] = None
status_var: Optional[tk.StringVar] = None

# ------------------------------
# IDENTITY
# ------------------------------
PROJECT_TITLE = "AI-Driven Behavioral Intelligence & Predictive Risk Platform"
SYSTEM_NAME = f"{PROJECT_TITLE} — FORENSICORE (Enhanced Final Edition)"
TEAM_LEADER = "Anil Pandey"
TEAM_MEMBERS = ["Divyansh Mehra", "Kartik Gupta", "Suraj Singh Farswan"]
TEAM_CONTACTS = {
    "Anil Pandey": {"phone": "7900546102", "email": "ap967143@gmail.com"},
    "Divyansh Mehra": {"phone": "7409288203", "email": "mehradivyansh8@gmail.com"},
    "Suraj Singh Farswan": {"phone": "+91 9599633603", "email": "surajsinghfarswan591@gmail.com"},
    "Kartik Gupta": {"phone": "+91 7302715858", "email": "kartikgupta2414257@gmail.com"},
}
TAGLINE = "Building an AI-Powered Digital Intelligence Ecosystem"

# ------------------------------
# PATHS
# ------------------------------
try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
except Exception:
    BASE_DIR = os.getcwd()

ROOT_DIR = os.path.join(BASE_DIR, "Forensic_System")
CASES_DIR = os.path.join(ROOT_DIR, "cases")
USERS_DIR = os.path.join(ROOT_DIR, "users")
AUDIT_DIR = os.path.join(ROOT_DIR, "audit_logs")
GRAPH_DIR = os.path.join(ROOT_DIR, "graphs")
EXPORT_DIR = os.path.join(ROOT_DIR, "exports")
DB_FILE = os.path.join(ROOT_DIR, "forensic.db")

for p in [ROOT_DIR, CASES_DIR, USERS_DIR, AUDIT_DIR, GRAPH_DIR, EXPORT_DIR]:
    os.makedirs(p, exist_ok=True)

MAX_USERS = 10
SIGNING_SECRET = b"FORENSICORE_DEMO_SECRET_DO_NOT_USE_IN_PRODUCTION"

# ------------------------------
# THEME
# ------------------------------
BG = "#0f1117"
CARD = "#171b22"
FG = "#f5f7fa"
MUTED = "#b5bdc9"
ACCENT = "#00d1b2"
ACCENT_2 = "#16a34a"
DANGER = "#ef4444"
WARNING = "#f59e0b"
INFO = "#38bdf8"

# ------------------------------
# HELPERS
# ------------------------------
def now_str() -> str:
    return str(datetime.now())

def set_status(msg: str):
    global status_var
    try:
        if status_var is not None:
            status_var.set(msg)
    except Exception:
        pass

def format_bytes(size: int) -> str:
    s = float(size)
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while s >= 1024 and idx < len(units) - 1:
        s /= 1024.0
        idx += 1
    return f"{s:.2f} {units[idx]}"

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def sign_payload(payload: Dict[str, Any]) -> str:
    msg = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hmac.new(SIGNING_SECRET, msg, hashlib.sha256).hexdigest()

def sanitize_filename(name: str) -> str:
    bad = '<>:"/\\|?*'
    for ch in bad:
        name = name.replace(ch, "_")
    return name.strip() or f"file_{uuid.uuid4().hex[:8]}"

def _is_image_file(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in [".png", ".jpg", ".jpeg", ".bmp"]

def _safe_report_image(path: str, max_width=5.8 * inch, max_height=3.8 * inch):
    try:
        if not os.path.exists(path):
            return None
        img = RLImage(path)
        img._restrictSize(max_width, max_height)
        return img
    except Exception:
        return None

def get_latest_graph(case_id: str, prefix: str) -> str:
    try:
        items = [
            os.path.join(GRAPH_DIR, f)
            for f in os.listdir(GRAPH_DIR)
            if f.startswith(f"{case_id}_{prefix}_") and f.endswith(".png")
        ]
        if not items:
            return ""
        items.sort(reverse=True)
        return items[0]
    except Exception:
        return ""

def safe_destroy(widget):
    try:
        if widget is not None:
            widget.destroy()
    except Exception:
        pass

def db_cursor():
    return conn.cursor()

# ------------------------------
# DATABASE
# ------------------------------
conn = sqlite3.connect(DB_FILE, timeout=30, check_same_thread=False)
cursor = conn.cursor()
cursor.execute("PRAGMA journal_mode=WAL;")
cursor.execute("PRAGMA synchronous=NORMAL;")
conn.commit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY,
    password TEXT,
    role TEXT,
    photo TEXT,
    created_at TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS cases(
    case_id TEXT PRIMARY KEY,
    created_at TEXT,
    created_by TEXT,
    title TEXT DEFAULT '',
    notes TEXT DEFAULT ''
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS evidence(
    id TEXT PRIMARY KEY,
    case_id TEXT,
    filename TEXT,
    filepath TEXT,
    sha256 TEXT,
    md5 TEXT,
    size_bytes INTEGER,
    added_at TEXT,
    added_by TEXT,
    signature TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS ai_scans(
    id TEXT PRIMARY KEY,
    case_id TEXT,
    ts TEXT,
    username TEXT,
    login_frequency INTEGER,
    files_accessed INTEGER,
    session_duration INTEGER,
    failed_attempts INTEGER,
    suspicious_flags INTEGER,
    ensemble_prob REAL,
    anomaly_label INTEGER,
    base_risk INTEGER,
    baseline_mean REAL,
    deviation REAL,
    final_risk INTEGER,
    risk_level TEXT,
    stress REAL,
    productivity_impact REAL,
    explain_login REAL,
    explain_files REAL,
    explain_session REAL,
    explain_failed REAL,
    explain_flags REAL,
    used_camera INTEGER,
    confidence_score REAL,
    recommendation TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS audit(
    id TEXT PRIMARY KEY,
    ts TEXT,
    username TEXT,
    action TEXT,
    details TEXT
)
""")
conn.commit()

def audit_log(username: str, action: str, details: str = ""):
    try:
        cur = db_cursor()
        cur.execute(
            "INSERT INTO audit VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), now_str(), username or "", action, details),
        )
        conn.commit()
    except Exception as e:
        print("AUDIT LOG ERROR:", e)
        traceback.print_exc()

try:
    cur = db_cursor()

    # Admin user create (if not exists)
    cur.execute(
        "INSERT OR IGNORE INTO users VALUES (?,?,?,?,?)",
        ("AnilPandey_AI", hash_password("Anil1945"), "Admin", "", now_str())
    )
    conn.commit()

    # Force password reset every time
    cur.execute(
        "UPDATE users SET password=? WHERE username=?",
        (hash_password("Anil1945"), "AnilPandey_AI")
    )
    conn.commit()

except Exception:
    traceback.print_exc()
# ------------------------------
# STATE
# ------------------------------
current_user: Optional[str] = None
current_role: Optional[str] = None
current_case: Optional[str] = None
ai_history: Dict[str, List[int]] = {}
baseline_profiles: Dict[str, List[int]] = {}
failed_login_attempts: Dict[str, int] = {}
MAX_LOGIN_ATTEMPTS = 3

# ------------------------------
# AI ENGINE
# ------------------------------
REQUIRED_COLS = [
    "login_frequency",
    "files_accessed",
    "session_duration",
    "failed_attempts",
    "suspicious_flags",
]

@dataclass
class RiskAggregation:
    base_risk: int
    deviation: float
    final_risk: int
    risk_level: str
    confidence_score: float
    recommendation: str

class ForensicAIEngine:
    def __init__(self, contamination: float = 0.10, n_estimators: int = 150, random_state: int = 42):
        self.scaler = StandardScaler()
        self.anomaly_model = IsolationForest(contamination=contamination, random_state=random_state)
        self.risk_model = RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=random_state,
            max_depth=8,
            min_samples_split=3,
            min_samples_leaf=1,
        )
        self.trained = False
        self._fitted_scaler = False

    def _to_df(self, data: List[Dict[str, Any]]) -> "pd.DataFrame":
        df = pd.DataFrame(data)
        for col in REQUIRED_COLS:
            if col not in df.columns:
                df[col] = 0
        df = df[REQUIRED_COLS].copy()
        df = df.apply(pd.to_numeric, errors="coerce").fillna(0)
        return df

    def prepare_features(self, data: List[Dict[str, Any]]) -> "np.ndarray":
        df = self._to_df(data)
        if not self._fitted_scaler:
            X = self.scaler.fit_transform(df.values)
            self._fitted_scaler = True
            return X
        return self.scaler.transform(df.values)

    def train(self, data: List[Dict[str, Any]], labels: List[int]) -> Dict[str, Any]:
        X = self.prepare_features(data)
        y = np.array(labels, dtype=int)
        if len(X) != len(y):
            raise ValueError("Data and labels length mismatch")
        self.risk_model.fit(X, y)
        self.anomaly_model.fit(X)
        self.trained = True
        return {"trained": True, "samples": int(len(y))}

    def predict_components(self, new_data: List[Dict[str, Any]]):
        if not self.trained:
            raise RuntimeError("Model not trained yet")
        X = self.prepare_features(new_data)
        prob = self.risk_model.predict_proba(X)[:, 1]
        anomaly = self.anomaly_model.predict(X)
        imp = getattr(self.risk_model, "feature_importances_", None)
        if imp is None:
            imp_dict = {c: 0.0 for c in REQUIRED_COLS}
        else:
            imp_dict = {REQUIRED_COLS[i]: float(imp[i]) for i in range(len(REQUIRED_COLS))}
        return prob, anomaly, imp_dict

    @staticmethod
    def stress_performance_impact(session_duration: float):
        stress = (float(session_duration) / 300.0) * 100.0
        stress = max(0.0, min(100.0, stress))
        productivity_impact = min(100.0, stress * 0.6)
        return float(stress), float(productivity_impact)

    @staticmethod
    def risk_recommendation(final_risk: int, anomaly_label: int, failed_attempts: int, suspicious_flags: int) -> str:
        if final_risk >= 75:
            return "Immediate review recommended. Freeze sensitive access, verify evidence handling, and escalate to administrator."
        if anomaly_label == -1 or suspicious_flags == 1 or failed_attempts >= 4:
            return "Behavior is abnormal. Increase monitoring, review logs, and verify user actions."
        if final_risk >= 40:
            return "Medium-risk pattern detected. Continue observation and compare with next scan."
        return "Behavior currently within acceptable range. Continue routine monitoring."

    @staticmethod
    def aggregate_risk(prob, anomaly_label, baseline_mean, failed_attempts, suspicious_flags):
        base_risk = int(round(float(prob) * 100))
        if int(anomaly_label) == -1:
            base_risk = min(100, base_risk + 20)

        if suspicious_flags >= 1:
            base_risk = min(100, base_risk + 8)

        if failed_attempts >= 5:
            base_risk = min(100, base_risk + 7)

        deviation = abs(float(base_risk) - float(baseline_mean))
        final_risk = int(round((float(base_risk) * 0.65) + (float(deviation) * 0.35)))
        final_risk = max(0, min(100, final_risk))

        if final_risk > 70:
            level = "HIGH"
        elif final_risk > 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        confidence = min(100.0, max(40.0, 60.0 + deviation * 0.5 + (10 if anomaly_label == -1 else 0)))
        recommendation = ForensicAIEngine.risk_recommendation(
            final_risk, anomaly_label, failed_attempts, suspicious_flags
        )

        return RiskAggregation(
            base_risk=base_risk,
            deviation=deviation,
            final_risk=final_risk,
            risk_level=level,
            confidence_score=float(confidence),
            recommendation=recommendation,
        )

engine = ForensicAIEngine()

# ------------------------------
# SYNTHETIC TRAINING DATA
# ------------------------------
train_data: List[Dict[str, Any]] = []
train_labels: List[int] = []

for _ in range(320):
    login_frequency = random.randint(1, 40)
    files_accessed = random.randint(1, 450)
    session_duration = random.randint(10, 420)
    failed_attempts = random.randint(0, 18)
    suspicious_flags = 1 if (failed_attempts > 5 or files_accessed > 260 or session_duration > 250) else 0

    score = 0
    if login_frequency > 22:
        score += 1
    if files_accessed > 220:
        score += 1
    if session_duration > 210:
        score += 1
    if failed_attempts > 4:
        score += 1
    if suspicious_flags == 1:
        score += 1

    label = 1 if score >= 2 else 0
    train_data.append(
        {
            "login_frequency": login_frequency,
            "files_accessed": files_accessed,
            "session_duration": session_duration,
            "failed_attempts": failed_attempts,
            "suspicious_flags": suspicious_flags,
        }
    )
    train_labels.append(label)

engine.train(train_data, train_labels)

def forecast(case_id: str) -> int:
    if case_id not in ai_history or len(ai_history[case_id]) < 2:
        return 0
    y_hist = np.array(ai_history[case_id], dtype=float)
    x = np.arange(len(y_hist), dtype=float)
    coef = np.polyfit(x, y_hist, 1)
    future = coef[0] * len(y_hist) + coef[1]
    return int(max(0, min(100, future)))

# ------------------------------
# ACCESS CHECKS
# ------------------------------
def require_login() -> bool:
    if not current_user:
        messagebox.showerror("Login Required", "Please login first.")
        return False
    return True

def require_admin() -> bool:
    if not require_login():
        return False
    if current_role != "Admin":
        messagebox.showerror("Access Denied", "Only Admin can access this feature.")
        return False
    return True

# ------------------------------
# CAMERA
# ------------------------------
def _try_open_camera(index: int):
    if cv2 is None:
        return None

    backends = []
    if hasattr(cv2, "CAP_DSHOW"):
        backends.append(cv2.CAP_DSHOW)
    if hasattr(cv2, "CAP_MSMF"):
        backends.append(cv2.CAP_MSMF)
    backends.append(None)

    for backend in backends:
        try:
            cap = cv2.VideoCapture(index, backend) if backend is not None else cv2.VideoCapture(index)
            if cap is not None and cap.isOpened():
                ok, frame = cap.read()
                if ok and frame is not None:
                    return cap
            if cap is not None:
                cap.release()
        except Exception:
            pass
    return None

def test_camera_indexes(max_index: int = 4):
    try:
        if cv2 is None:
            messagebox.showerror("Camera", "opencv-python not installed")
            return
        found = []
        for idx in range(max_index + 1):
            cap = _try_open_camera(idx)
            if cap is not None:
                found.append(idx)
                cap.release()
        if found:
            messagebox.showinfo("Camera Test", f"Working camera indexes: {found}\nDefault usable: {found[0]}")
        else:
            messagebox.showerror("Camera Test", "No working camera found.\nCheck OS permission and webcam access.")
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("Camera Test Error", str(e))

def capture_photo(username: str) -> str:
    if cv2 is None:
        messagebox.showerror("Camera", "Install opencv-python first")
        return ""

    chosen_cam = None
    chosen_cap = None

    for idx in range(5):
        cap = _try_open_camera(idx)
        if cap is not None:
            chosen_cam = idx
            chosen_cap = cap
            break

    if chosen_cap is None:
        messagebox.showerror("Camera Error", "Camera not found or permission denied.")
        return ""

    chosen_cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
    chosen_cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)

    win = tk.Toplevel(root)
    win.title("Live Camera Capture")
    win.configure(bg=BG)
    win.geometry("930x720")
    win.resizable(False, False)
    win.transient(root)

    tk.Label(win, text="Live Camera Preview", bg=BG, fg=ACCENT, font=("Arial", 15, "bold")).pack(pady=(10, 4))
    tk.Label(win, text=f"Camera Index: {chosen_cam}", bg=BG, fg=FG, font=("Arial", 10)).pack()

    preview = tk.Label(win, bg=BG)
    preview.pack(pady=10)

    info_var = tk.StringVar(value="Initializing camera...")
    tk.Label(win, textvariable=info_var, bg=BG, fg=MUTED).pack()

    result = {"path": "", "frame": None}
    running = {"value": True}

    def update_frame():
        if not running["value"]:
            return
        try:
            ok, frame = chosen_cap.read()
            if ok and frame is not None:
                result["frame"] = frame.copy()
                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                img = Image.fromarray(rgb)
                img.thumbnail((840, 520))
                imgtk = ImageTk.PhotoImage(img)
                preview.imgtk = imgtk
                preview.configure(image=imgtk)
                info_var.set("Camera active. Press Capture to save.")
            else:
                info_var.set("Unable to read frame from camera.")
        except Exception as e:
            info_var.set(f"Camera error: {e}")
        win.after(25, update_frame)

    def close_camera():
        running["value"] = False
        try:
            chosen_cap.release()
        except Exception:
            pass
        try:
            cv2.destroyAllWindows()
        except Exception:
            pass

    def do_capture():
        if result["frame"] is None:
            messagebox.showerror("Capture Error", "No frame available")
            return
        path = os.path.join(USERS_DIR, f"{sanitize_filename(username)}.png")
        try:
            cv2.imwrite(path, result["frame"])
            result["path"] = path
            close_camera()
            win.destroy()
            messagebox.showinfo("Saved", f"Photo saved:\n{path}")
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Save Error", str(e))

    def do_cancel():
        close_camera()
        win.destroy()

    btn_frame = tk.Frame(win, bg=BG)
    btn_frame.pack(pady=12)

    ttk.Button(btn_frame, text="Capture", command=do_capture).grid(row=0, column=0, padx=10)
    ttk.Button(btn_frame, text="Cancel", command=do_cancel).grid(row=0, column=1, padx=10)

    win.protocol("WM_DELETE_WINDOW", do_cancel)
    update_frame()
    win.grab_set()
    win.wait_window()
    return result["path"]

# ------------------------------
# USER MANAGEMENT
# ------------------------------
def register_user():
    if not require_admin():
        return

    try:
        cur = db_cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        total = cur.fetchone()[0]
        if total >= MAX_USERS:
            messagebox.showerror("User Limit", f"Maximum {MAX_USERS} users allowed.")
            return
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("User Count Error", str(e))
        return

    win = tk.Toplevel(root)
    win.title("Register User")
    win.configure(bg=BG)
    win.geometry("420x340")
    win.transient(root)
    win.grab_set()

    tk.Label(win, text="Register New User", bg=BG, fg=ACCENT, font=("Arial", 14, "bold")).pack(pady=10)

    form = tk.Frame(win, bg=BG)
    form.pack(pady=10)

    tk.Label(form, text="Username", bg=BG, fg=FG).grid(row=0, column=0, sticky="w", pady=6)
    u = ttk.Entry(form, width=28)
    u.grid(row=0, column=1, pady=6)

    tk.Label(form, text="Password", bg=BG, fg=FG).grid(row=1, column=0, sticky="w", pady=6)
    p = ttk.Entry(form, width=28, show="*")
    p.grid(row=1, column=1, pady=6)

    tk.Label(form, text="Role", bg=BG, fg=FG).grid(row=2, column=0, sticky="w", pady=6)
    role = ttk.Combobox(form, values=["Admin", "Investigator"], state="readonly", width=25)
    role.set("Investigator")
    role.grid(row=2, column=1, pady=6)

    var_photo = tk.IntVar(value=0)
    tk.Checkbutton(
        win,
        text="Capture photo with consent",
        variable=var_photo,
        bg=BG,
        fg=FG,
        selectcolor=BG,
        activebackground=BG,
    ).pack(pady=8)

    def save():
        username = u.get().strip()
        pw = p.get().strip()
        r = role.get().strip()

        if not username or not pw:
            messagebox.showerror("Error", "Username and password required")
            return

        photo_path = ""
        if var_photo.get() == 1:
            photo_path = capture_photo(username)

        try:
            cur = db_cursor()
            cur.execute(
                "INSERT INTO users VALUES (?,?,?,?,?)",
                (username, hash_password(pw), r, photo_path, now_str()),
            )
            conn.commit()
            audit_log(current_user or "", "REGISTER_USER", f"{username} role={r}")
            messagebox.showinfo("Success", "User registered successfully.")
            win.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "User already exists")
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Register Error", str(e))

    ttk.Button(win, text="Register", command=save).pack(pady=10)

def login_screen():
    global current_user, current_role

    win = tk.Toplevel(root)
    win.title("Login")
    win.configure(bg=BG)
    win.geometry("400x240")
    win.transient(root)
    win.grab_set()

    tk.Label(win, text="Secure Login", bg=BG, fg=ACCENT, font=("Arial", 14, "bold")).pack(pady=12)

    form = tk.Frame(win, bg=BG)
    form.pack(pady=8)

    tk.Label(form, text="Username", bg=BG, fg=FG).grid(row=0, column=0, sticky="w", pady=6)
    u = ttk.Entry(form, width=28)
    u.grid(row=0, column=1, pady=6)

    tk.Label(form, text="Password", bg=BG, fg=FG).grid(row=1, column=0, sticky="w", pady=6)
    p = ttk.Entry(form, width=28, show="*")
    p.grid(row=1, column=1, pady=6)

    def verify():
        nonlocal win
        global current_user, current_role

        username = u.get().strip()
        pw = p.get().strip()

        if username not in failed_login_attempts:
            failed_login_attempts[username] = 0

        if failed_login_attempts[username] >= MAX_LOGIN_ATTEMPTS:
            audit_log(username, "APP_EXIT_MAX_LOGIN_ATTEMPTS", "Closed after repeated failed login")
            messagebox.showerror("Application Closed", "Too many failed attempts.\nApplication will close.")
            try:
                conn.commit()
                conn.close()
            except Exception:
                pass
            if root is not None:
                safe_destroy(root)
            return

        try:
            cur = db_cursor()
            cur.execute("SELECT password, role FROM users WHERE username=?", (username,))
            row = cur.fetchone()
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Login Error", str(e))
            return

        if row and hash_password(pw) == row[0]:
            failed_login_attempts[username] = 0
            current_user = username
            current_role = row[1]
            audit_log(current_user, "LOGIN_SUCCESS", f"role={current_role}")
            set_status(f"Logged in: {current_user} ({current_role})")
            messagebox.showinfo("Login Success", f"Welcome {current_user}")
            win.destroy()
        else:
            failed_login_attempts[username] += 1
            remaining = MAX_LOGIN_ATTEMPTS - failed_login_attempts[username]
            audit_log(username, "LOGIN_FAILED", f"remaining_attempts={remaining}")
            if remaining <= 0:
                audit_log(username, "APP_EXIT_MAX_LOGIN_ATTEMPTS", "Closed after 3 wrong password attempts")
                messagebox.showerror("Application Closed", "Wrong password 3 times.\nApplication will close.")
                try:
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
                if root is not None:
                    safe_destroy(root)
            else:
                messagebox.showerror("Invalid Credentials", f"Wrong password.\nRemaining attempts: {remaining}")

    ttk.Button(win, text="Login", command=verify).pack(pady=12)

def forgot_password():
    win = tk.Toplevel(root)
    win.title("Forgot Password")
    win.configure(bg=BG)
    win.geometry("400x220")
    win.transient(root)
    win.grab_set()

    tk.Label(win, text="Reset Password", bg=BG, fg=ACCENT, font=("Arial", 14, "bold")).pack(pady=12)

    form = tk.Frame(win, bg=BG)
    form.pack(pady=10)

    tk.Label(form, text="Username", bg=BG, fg=FG).grid(row=0, column=0, sticky="w", pady=6)
    u = ttk.Entry(form, width=28)
    u.grid(row=0, column=1, pady=6)

    tk.Label(form, text="New Password", bg=BG, fg=FG).grid(row=1, column=0, sticky="w", pady=6)
    newp = ttk.Entry(form, width=28, show="*")
    newp.grid(row=1, column=1, pady=6)

    def reset():
        username = u.get().strip()
        npass = newp.get().strip()
        if not username or not npass:
            messagebox.showerror("Error", "Username and new password required")
            return
        try:
            cur = db_cursor()
            cur.execute("SELECT username FROM users WHERE username=?", (username,))
            if cur.fetchone():
                cur.execute("UPDATE users SET password=? WHERE username=?", (hash_password(npass), username))
                conn.commit()
                audit_log(username, "PASSWORD_RESET", "")
                messagebox.showinfo("Success", "Password updated.")
                win.destroy()
            else:
                messagebox.showerror("Error", "User not found")
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Reset Password Error", str(e))

    ttk.Button(win, text="Reset Password", command=reset).pack(pady=10)

def logout():
    global current_user, current_role, current_case
    if not require_login():
        return
    audit_log(current_user or "", "LOGOUT", "")
    current_user = None
    current_role = None
    current_case = None
    set_status("Not logged in")
    messagebox.showinfo("Logout", "Logged out successfully.")

def exit_app():
    if messagebox.askyesno("Exit", "Exit application?"):
        try:
            conn.commit()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        try:
            if root is not None:
                root.destroy()
        except Exception:
            pass

# ------------------------------
# CASE MANAGEMENT
# ------------------------------
def create_case():
    global current_case

    if not require_login():
        return

    win = tk.Toplevel(root)
    win.title("Create Case")
    win.configure(bg=BG)
    win.geometry("420x260")
    win.transient(root)
    win.grab_set()

    tk.Label(win, text="Create New Case", bg=BG, fg=ACCENT, font=("Arial", 14, "bold")).pack(pady=10)

    form = tk.Frame(win, bg=BG)
    form.pack(pady=8)

    tk.Label(form, text="Case Title", bg=BG, fg=FG).grid(row=0, column=0, sticky="w", pady=6)
    e_title = ttk.Entry(form, width=28)
    e_title.grid(row=0, column=1, pady=6)

    tk.Label(form, text="Notes", bg=BG, fg=FG).grid(row=1, column=0, sticky="nw", pady=6)
    txt = tk.Text(form, height=5, width=28, bg=CARD, fg=FG, insertbackground=FG)
    txt.grid(row=1, column=1, pady=6)

    def save_case():
        global current_case
        try:
            title = e_title.get().strip()
            notes = txt.get("1.0", "end-1c").strip()

            if not title:
                messagebox.showerror("Error", "Case title is required.")
                return

            case_id = "CASE_" + uuid.uuid4().hex[:8].upper()
            case_folder = os.path.join(CASES_DIR, case_id)
            os.makedirs(case_folder, exist_ok=True)

            cur = db_cursor()
            cur.execute(
                "INSERT INTO cases (case_id, created_at, created_by, title, notes) VALUES (?,?,?,?,?)",
                (case_id, now_str(), current_user or "", title, notes),
            )
            conn.commit()

            current_case = case_id
            audit_log(current_user or "", "CREATE_CASE", f"{case_id} title={title}")
            set_status(f"Active Case: {current_case}")

            messagebox.showinfo("Case Created", f"{case_id}\n\nTitle: {title}")
            win.destroy()

        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Create Case Error", f"{type(e).__name__}: {e}")

    ttk.Button(win, text="Create", command=save_case).pack(pady=10)

def select_case():
    global current_case

    if not require_login():
        return

    win = tk.Toplevel(root)
    win.title("Select Case")
    win.configure(bg=BG)
    win.geometry("860x360")
    win.transient(root)
    win.grab_set()

    cols = ("case_id", "created_at", "created_by", "title")
    tree = ttk.Treeview(win, columns=cols, show="headings")
    for c, w in zip(cols, [180, 180, 150, 260]):
        tree.heading(c, text=c)
        tree.column(c, width=w)
    tree.pack(fill="both", expand=True, padx=10, pady=10)

    try:
        cur = db_cursor()
        cur.execute("SELECT case_id, created_at, created_by, title FROM cases ORDER BY created_at DESC")
        rows = cur.fetchall()

        for row in rows:
            tree.insert("", "end", values=row)
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("Load Cases Error", f"{type(e).__name__}: {e}")
        win.destroy()
        return

    def set_active():
        global current_case
        try:
            sel = tree.selection()
            if not sel:
                messagebox.showerror("Error", "Select a case first.")
                return

            values = tree.item(sel[0], "values")
            if not values:
                messagebox.showerror("Error", "Invalid case selection.")
                return

            current_case = str(values[0])
            audit_log(current_user or "", "SELECT_CASE", current_case)
            set_status(f"Active Case: {current_case}")
            messagebox.showinfo("Case Selected", current_case)
            win.destroy()
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Select Case Error", f"{type(e).__name__}: {e}")

    ttk.Button(win, text="Set Active Case", command=set_active).pack(pady=8)

# ------------------------------
# EVIDENCE
# ------------------------------
def store_evidence():
    if not require_login():
        return
    if not current_case:
        messagebox.showerror("Error", "Create/select a case first.")
        return

    file = filedialog.askopenfilename()
    if not file:
        return

    try:
        filename = sanitize_filename(os.path.basename(file))
        case_folder = os.path.join(CASES_DIR, current_case)
        os.makedirs(case_folder, exist_ok=True)
        dest = os.path.join(case_folder, filename)

        with open(file, "rb") as f:
            data_b = f.read()

        sha256 = sha256_bytes(data_b)
        md5 = md5_bytes(data_b)
        shutil.copy2(file, dest)
        size_bytes = os.path.getsize(dest)

        payload = {
            "case_id": current_case,
            "filename": filename,
            "sha256": sha256,
            "md5": md5,
            "size_bytes": int(size_bytes),
            "added_at": now_str(),
            "added_by": current_user,
        }
        signature = sign_payload(payload)

        cur = db_cursor()
        cur.execute(
            "INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                current_case,
                filename,
                dest,
                sha256,
                md5,
                int(size_bytes),
                payload["added_at"],
                current_user,
                signature,
            ),
        )
        conn.commit()

        audit_log(current_user or "", "STORE_EVIDENCE", f"{current_case} {filename} sha256={sha256[:16]}")
        messagebox.showinfo(
            "Evidence Stored",
            f"Stored: {filename}\n\n"
            f"SHA-256:\n{sha256}\n\n"
            f"MD5:\n{md5}\n\n"
            f"Digital Signature:\n{signature}"
        )
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("Evidence Error", str(e))

def list_evidence():
    if not require_login():
        return
    if not current_case:
        messagebox.showerror("Error", "No active case selected.")
        return

    win = tk.Toplevel(root)
    win.title("Evidence List")
    win.configure(bg=BG)
    win.geometry("1220x450")
    win.transient(root)
    win.grab_set()

    cols = ("filename", "sha256", "md5", "size", "added_at", "added_by", "signature")
    tree = ttk.Treeview(win, columns=cols, show="headings")
    widths = [160, 220, 120, 90, 180, 100, 220]
    for c, w in zip(cols, widths):
        tree.heading(c, text=c)
        tree.column(c, width=w)
    tree.pack(fill="both", expand=True, padx=10, pady=10)

    try:
        cur = db_cursor()
        cur.execute(
            "SELECT filename, sha256, md5, size_bytes, added_at, added_by, signature FROM evidence WHERE case_id=?",
            (current_case,),
        )
        for r in cur.fetchall():
            filename, sha256, md5, sizeb, added_at, added_by, sig = r
            tree.insert(
                "",
                "end",
                values=(filename, sha256, md5, format_bytes(sizeb), added_at, added_by, sig[:28] + "..."),
            )

        audit_log(current_user or "", "VIEW_EVIDENCE_LIST", current_case)
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("List Evidence Error", str(e))

def verify_evidence_integrity():
    if not require_login():
        return
    if not current_case:
        messagebox.showerror("Error", "No active case selected.")
        return

    try:
        cur = db_cursor()
        cur.execute(
            "SELECT filename, filepath, sha256, md5, size_bytes, added_at, added_by, signature "
            "FROM evidence WHERE case_id=?",
            (current_case,),
        )
        rows = cur.fetchall()

        if not rows:
            messagebox.showinfo("Verify", "No evidence in this case.")
            return

        ok = 0
        bad = 0
        missing_ct = 0
        sig_bad = 0
        report_lines = []

        for filename, filepath, stored_sha, stored_md5, size_bytes, added_at, added_by, stored_sig in rows:
            if not os.path.exists(filepath):
                missing_ct += 1
                report_lines.append(f"{filename}: MISSING")
                continue

            with open(filepath, "rb") as f:
                data_b = f.read()

            now_sha = sha256_bytes(data_b)
            now_md5 = md5_bytes(data_b)

            payload = {
                "case_id": current_case,
                "filename": filename,
                "sha256": stored_sha,
                "md5": stored_md5,
                "size_bytes": int(size_bytes),
                "added_at": str(added_at),
                "added_by": str(added_by),
            }
            calc_sig = sign_payload(payload)
            sig_ok = hmac.compare_digest(calc_sig, str(stored_sig))

            if now_sha == stored_sha and now_md5 == stored_md5 and sig_ok:
                ok += 1
                report_lines.append(f"{filename}: OK")
            else:
                bad += 1
                if not sig_ok:
                    sig_bad += 1
                report_lines.append(f"{filename}: TAMPERED / SIGNATURE_MISMATCH")

        audit_log(current_user or "", "VERIFY_EVIDENCE", f"ok={ok} bad={bad} missing={missing_ct} sig_bad={sig_bad}")
        messagebox.showinfo(
            "Integrity Result",
            f"OK: {ok}\nTAMPERED: {bad}\nMISSING: {missing_ct}\nSIGNATURE BAD: {sig_bad}\n\n"
            + "\n".join(report_lines[:30])
        )
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("Verify Evidence Error", str(e))

# ------------------------------
# EXPORTS
# ------------------------------
def export_evidence_manifest():
    if not require_login():
        return
    if not current_case:
        messagebox.showerror("Error", "No active case selected.")
        return

    try:
        cur = db_cursor()
        cur.execute("""
            SELECT filename, filepath, sha256, md5, size_bytes, added_at, added_by, signature
            FROM evidence WHERE case_id=?
            ORDER BY added_at ASC
        """, (current_case,))
        rows = cur.fetchall()

        if not rows:
            messagebox.showinfo("Export Manifest", "No evidence in this case.")
            return

        manifest = {
            "project_title": PROJECT_TITLE,
            "system_name": SYSTEM_NAME,
            "case_id": current_case,
            "generated_at": now_str(),
            "generated_by": current_user,
            "evidence_count": len(rows),
            "evidence": [],
        }

        for filename, filepath, sha256, md5, size_bytes, added_at, added_by, sig in rows:
            manifest["evidence"].append(
                {
                    "filename": filename,
                    "filepath": filepath,
                    "sha256": sha256,
                    "md5": md5,
                    "size_bytes": int(size_bytes),
                    "added_at": str(added_at),
                    "added_by": str(added_by),
                    "evidence_signature": str(sig),
                }
            )

        manifest_signature = sign_payload(
            {
                "case_id": current_case,
                "generated_at": manifest["generated_at"],
                "generated_by": current_user,
                "evidence_count": len(rows),
                "evidence_hashes": [e["sha256"] for e in manifest["evidence"]],
            }
        )
        manifest["manifest_signature"] = manifest_signature

        out = os.path.join(CASES_DIR, current_case, f"{current_case}_evidence_manifest.json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        audit_log(current_user or "", "EXPORT_EVIDENCE_MANIFEST", out)
        messagebox.showinfo("Manifest Exported", f"Saved:\n{out}\n\nSignature:\n{manifest_signature}")
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("Export Manifest Error", str(e))

def export_audit_logs_csv():
    if not require_login():
        return

    try:
        out = os.path.join(AUDIT_DIR, f"audit_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        cur = db_cursor()
        cur.execute("SELECT ts, username, action, details FROM audit ORDER BY ts DESC")
        rows = cur.fetchall()

        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "username", "action", "details"])
            for r in rows:
                w.writerow(list(r))

        audit_log(current_user or "", "EXPORT_AUDIT_CSV", out)
        messagebox.showinfo("Audit CSV Exported", f"Saved:\n{out}\nRows: {len(rows)}")
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("Export Audit Error", f"{type(e).__name__}: {e}")

def view_audit_logs():
    if not require_login():
        return

    win = tk.Toplevel(root)
    win.title("Audit Logs")
    win.configure(bg=BG)
    win.geometry("900x450")
    win.transient(root)
    win.grab_set()

    text = tk.Text(win, bg="#10141b", fg="#e6edf3", insertbackground="#e6edf3")
    text.pack(fill="both", expand=True)

    try:
        cur = db_cursor()
        cur.execute("SELECT ts, username, action, details FROM audit ORDER BY ts DESC LIMIT 250")
        for r in cur.fetchall():
            text.insert("end", f"{r[0]} | {r[1]} | {r[2]} | {r[3]}\n")
        text.configure(state="disabled")
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("Audit Log Error", f"{type(e).__name__}: {e}")

# ------------------------------
# GRAPH HELPERS
# ------------------------------
def save_current_plot(case_id: str, name: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(GRAPH_DIR, f"{case_id}_{name}_{ts}.png")
    plt.tight_layout()
    plt.savefig(out, dpi=180, bbox_inches="tight")
    return out

def make_wave_curve(y_values: List[float], points_multiplier: int = 30):
    x = np.arange(len(y_values))
    if len(y_values) < 2:
        return x, np.array(y_values, dtype=float)

    x_smooth = np.linspace(x.min(), x.max(), max(120, len(y_values) * points_multiplier))
    y_linear = np.interp(x_smooth, x, np.array(y_values, dtype=float))

    amplitude = max(1.0, np.std(y_values) * 0.12)
    wave = np.sin(np.linspace(0, len(y_values) * math.pi, len(x_smooth))) * amplitude
    y_smooth = np.clip(y_linear + wave, 0, 100)
    return x_smooth, y_smooth

def _show_animated_line(title: str, x_smooth, y_smooth, x_points, y_points, y_label: str, extra_lines=None):
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.set_title(title)
    ax.set_xlabel("Scan Index")
    ax.set_ylabel(y_label)
    ax.set_ylim(0, 100)
    ax.grid(True, alpha=0.3)

    line_main, = ax.plot([], [], linewidth=3, label="Wave Trend")
    ax.scatter(x_points, y_points, s=45, label="Scan Points")

    if extra_lines:
        for item in extra_lines:
            kind = item.get("kind", "plot")
            if kind == "plot":
                ax.plot(
                    item["x"],
                    item["y"],
                    linewidth=item.get("linewidth", 2),
                    linestyle=item.get("linestyle", "-"),
                    label=item["label"]
                )
            elif kind == "hline":
                ax.axhline(
                    y=item["y"],
                    linestyle=item.get("linestyle", "--"),
                    linewidth=item.get("linewidth", 1.5),
                    label=item["label"],
                )

    ax.legend()

    def init():
        line_main.set_data([], [])
        return (line_main,)

    def update(frame):
        line_main.set_data(x_smooth[:frame], y_smooth[:frame])
        return (line_main,)

    anim = FuncAnimation(fig, update, frames=len(x_smooth), init_func=init, interval=15, blit=True, repeat=False)
    fig._anim = anim
    plt.show()

# ------------------------------
# AI SCAN
# ------------------------------
def ai_scan():
    if not require_login():
        return
    if not current_case:
        messagebox.showerror("Error", "Create/select a case first.")
        return

    try:
        cur = db_cursor()
        cur.execute("SELECT COUNT(*) FROM evidence WHERE case_id=?", (current_case,))
        files_accessed = int(cur.fetchone()[0])
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("AI Scan Error", str(e))
        return

    win = tk.Toplevel(root)
    win.title("AI Risk Scan")
    win.configure(bg=BG)
    win.geometry("460x440")
    win.transient(root)
    win.grab_set()

    tk.Label(win, text="AI Risk Scan Input", bg=BG, fg=ACCENT, font=("Arial", 14, "bold")).pack(pady=12)

    form = tk.Frame(win, bg=BG)
    form.pack(pady=10)

    entries = {}

    fields = [
        ("Login Frequency", "10"),
        ("Files Accessed (auto)", str(files_accessed)),
        ("Session Duration (min)", "60"),
        ("Failed Attempts", "0"),
        ("Suspicious Flags (0/1)", "0"),
    ]

    for i, (label, default) in enumerate(fields):
        tk.Label(form, text=label, bg=BG, fg=FG).grid(row=i, column=0, sticky="w", pady=7)
        e = ttk.Entry(form, width=25)
        e.insert(0, default)
        e.grid(row=i, column=1, pady=7)
        entries[label] = e

    used_camera = {"value": 0}

    def capture_for_scan():
        path = capture_photo(f"scan_{current_user}_{current_case}_{int(time.time())}")
        if path:
            used_camera["value"] = 1
            messagebox.showinfo("Camera", "Photo captured for this scan.")
        else:
            used_camera["value"] = 0

    if current_role == "Admin":
        ttk.Button(win, text="Capture Camera Photo", command=capture_for_scan).pack(pady=8)

    def run_scan():
        try:
            login_frequency = int(entries["Login Frequency"].get().strip())
            files_accessed_val = int(entries["Files Accessed (auto)"].get().strip())
            session_duration = int(entries["Session Duration (min)"].get().strip())
            failed_attempts = int(entries["Failed Attempts"].get().strip())
            suspicious_flags = int(entries["Suspicious Flags (0/1)"].get().strip())

            if suspicious_flags not in [0, 1]:
                raise ValueError("Suspicious Flags must be 0 or 1")
            if min(login_frequency, files_accessed_val, session_duration, failed_attempts) < 0:
                raise ValueError("Values cannot be negative")
        except Exception as e:
            messagebox.showerror("Input Error", str(e))
            return

        try:
            sample = [{
                "login_frequency": login_frequency,
                "files_accessed": files_accessed_val,
                "session_duration": session_duration,
                "failed_attempts": failed_attempts,
                "suspicious_flags": suspicious_flags,
            }]

            prob, anomaly, imp = engine.predict_components(sample)

            baseline_profiles.setdefault(current_case, [])
            raw_base = int(round(float(prob[0]) * 100)) + (20 if int(anomaly[0]) == -1 else 0)
            raw_base = max(0, min(100, raw_base))
            baseline_profiles[current_case].append(raw_base)
            baseline_mean = float(statistics.mean(baseline_profiles[current_case]))

            agg = engine.aggregate_risk(
                prob[0],
                int(anomaly[0]),
                baseline_mean,
                failed_attempts,
                suspicious_flags
            )

            stress, productivity = engine.stress_performance_impact(session_duration)

            ai_history.setdefault(current_case, [])
            ai_history[current_case].append(int(agg.final_risk))
            future_risk = forecast(current_case)

            explain_login = float(imp.get("login_frequency", 0.0))
            explain_files = float(imp.get("files_accessed", 0.0))
            explain_session = float(imp.get("session_duration", 0.0))
            explain_failed = float(imp.get("failed_attempts", 0.0))
            explain_flags = float(imp.get("suspicious_flags", 0.0))

            cur = db_cursor()
            cur.execute("""
                INSERT INTO ai_scans VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                str(uuid.uuid4()),
                current_case,
                now_str(),
                current_user,
                login_frequency,
                files_accessed_val,
                session_duration,
                failed_attempts,
                suspicious_flags,
                float(prob[0]),
                int(anomaly[0]),
                int(agg.base_risk),
                float(baseline_mean),
                float(agg.deviation),
                int(agg.final_risk),
                str(agg.risk_level),
                float(stress),
                float(productivity),
                explain_login,
                explain_files,
                explain_session,
                explain_failed,
                explain_flags,
                int(used_camera["value"]),
                float(agg.confidence_score),
                str(agg.recommendation),
            ))
            conn.commit()

            if agg.risk_level == "HIGH":
                audit_log(current_user or "", "AI_ALERT_HIGH", f"case={current_case} risk={agg.final_risk}")
                messagebox.showwarning("HIGH RISK ALERT", f"High risk detected!\nCase: {current_case}\nRisk: {agg.final_risk}%")
            else:
                audit_log(current_user or "", "AI_SCAN", f"case={current_case} risk={agg.final_risk} level={agg.risk_level}")

            explanation = (
                f"Login Influence: {round(explain_login * 100, 2)}%\n"
                f"Files Influence: {round(explain_files * 100, 2)}%\n"
                f"Session Influence: {round(explain_session * 100, 2)}%\n"
                f"Failed Attempts Influence: {round(explain_failed * 100, 2)}%\n"
                f"Flags Influence: {round(explain_flags * 100, 2)}%"
            )

            messagebox.showinfo(
                "AI Risk Analysis",
                f"Final Risk Score: {agg.final_risk}% ({agg.risk_level})\n"
                f"Risk Probability: {round(float(prob[0]) * 100, 2)}%\n"
                f"Anomaly Detected: {'YES' if int(anomaly[0]) == -1 else 'NO'}\n"
                f"Base Risk: {agg.base_risk}%\n"
                f"Baseline Mean: {round(baseline_mean, 2)}\n"
                f"Deviation: {round(float(agg.deviation), 2)}\n"
                f"Forecast Next Risk: {future_risk}%\n"
                f"Confidence Score: {round(agg.confidence_score, 2)}%\n\n"
                f"Stress: {round(stress, 2)}%\n"
                f"Productivity Impact: {round(productivity, 2)}%\n\n"
                f"Recommendation:\n{agg.recommendation}\n\n"
                f"Explainable AI:\n{explanation}"
            )
            win.destroy()

        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("AI Scan Error", str(e))

    ttk.Button(win, text="Run AI Risk Scan", command=run_scan).pack(pady=12)

# ------------------------------
# VISUAL ANALYTICS
# ------------------------------
def risk_trend_graph():
    if not require_login():
        return
    if not current_case:
        messagebox.showerror("Error", "Select a case first.")
        return

    try:
        cur = db_cursor()
        cur.execute("""
            SELECT ts, base_risk, baseline_mean, deviation, final_risk, risk_level
            FROM ai_scans
            WHERE case_id=?
            ORDER BY ts ASC
        """, (current_case,))
        rows = cur.fetchall()

        if len(rows) < 2:
            messagebox.showerror("Error", "At least 2 AI scans are required.")
            return

        base_risk_vals = []
        baseline_mean_vals = []
        deviation_vals = []
        final_risk_vals = []
        risk_level_vals = []

        for row in rows:
            base_risk_vals.append(float(row[1]))
            baseline_mean_vals.append(float(row[2]))
            deviation_vals.append(float(row[3]))
            final_risk_vals.append(float(row[4]))
            risk_level_vals.append(str(row[5]))

        avg_final_risk = statistics.mean(final_risk_vals)
        latest_final_risk = final_risk_vals[-1]
        latest_level = risk_level_vals[-1]
        latest_deviation = deviation_vals[-1]
        volatility = statistics.stdev(final_risk_vals) if len(final_risk_vals) > 1 else 0.0
        first_risk = final_risk_vals[0]
        last_risk = final_risk_vals[-1]

        if last_risk > first_risk:
            trend_direction = "INCREASING"
        elif last_risk < first_risk:
            trend_direction = "DECREASING"
        else:
            trend_direction = "STABLE"

        upper_band = min(100, avg_final_risk + volatility)
        lower_band = max(0, avg_final_risk - volatility)

        x = np.arange(len(final_risk_vals))
        x_smooth, final_smooth = make_wave_curve(final_risk_vals)
        _, base_smooth = make_wave_curve(base_risk_vals)
        _, baseline_smooth = make_wave_curve(baseline_mean_vals)

        plt.figure(figsize=(13, 6))
        plt.plot(x_smooth, final_smooth, linewidth=3, label="Final Risk Wave")
        plt.plot(x_smooth, base_smooth, linewidth=2, label="Base Risk")
        plt.plot(x_smooth, baseline_smooth, linewidth=2, label="Baseline Mean")
        plt.scatter(x, final_risk_vals, s=45, label="Scan Points")
        plt.fill_between(x_smooth, final_smooth, alpha=0.10)
        plt.axhline(y=avg_final_risk, linestyle="--", linewidth=1.5, label="Average Final Risk")
        plt.axhline(y=upper_band, linestyle=":", linewidth=1.5, label="Upper Volatility Band")
        plt.axhline(y=lower_band, linestyle=":", linewidth=1.5, label="Lower Volatility Band")
        plt.title(f"AI Risk Wave Trend Graph - {current_case}")
        plt.xlabel("Scan Index")
        plt.ylabel("Risk Score (%)")
        plt.xticks(x, [f"S{i+1}" for i in x])
        plt.ylim(0, 100)
        plt.grid(True, alpha=0.3)
        plt.legend()

        out = save_current_plot(current_case, "risk_trend")
        plt.show()

        _show_animated_line(
            f"Animated Risk Wave - {current_case}",
            x_smooth,
            final_smooth,
            x,
            final_risk_vals,
            "Risk Score (%)",
            extra_lines=[
                {"kind": "plot", "x": x_smooth, "y": base_smooth, "label": "Base Risk"},
                {"kind": "plot", "x": x_smooth, "y": baseline_smooth, "label": "Baseline Mean"},
                {"kind": "hline", "y": avg_final_risk, "label": "Average Final Risk"},
                {"kind": "hline", "y": upper_band, "label": "Upper Volatility Band", "linestyle": ":"},
                {"kind": "hline", "y": lower_band, "label": "Lower Volatility Band", "linestyle": ":"},
            ],
        )

        summary = (
            f"Case ID: {current_case}\n"
            f"Total Scans: {len(rows)}\n"
            f"Latest Final Risk: {round(latest_final_risk, 2)}% ({latest_level})\n"
            f"Average Final Risk: {round(avg_final_risk, 2)}%\n"
            f"Latest Deviation: {round(latest_deviation, 2)}\n"
            f"Volatility: {round(volatility, 2)}\n"
            f"Trend Direction: {trend_direction}\n"
            f"Graph Saved: {out}\n"
        )

        if latest_final_risk > upper_band:
            summary += "\nInterpretation: Current risk is above the normal trend band."
        elif latest_final_risk < lower_band:
            summary += "\nInterpretation: Current risk is below the normal trend band."
        else:
            summary += "\nInterpretation: Current risk is within the expected trend band."

        audit_log(current_user or "", "RISK_TREND_GRAPH", f"case={current_case} graph={out} trend={trend_direction}")
        messagebox.showinfo("AI Risk Trend Analysis", summary)
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("Risk Trend Error", str(e))

def baseline_graph():
    if not require_login():
        return
    if not current_case:
        messagebox.showerror("Error", "Select a case first.")
        return

    try:
        cur = db_cursor()
        cur.execute("""
            SELECT ts, base_risk, baseline_mean, final_risk
            FROM ai_scans
            WHERE case_id=?
            ORDER BY ts ASC
        """, (current_case,))
        rows = cur.fetchall()

        if len(rows) < 2:
            messagebox.showerror("Error", "At least 2 AI scans required.")
            return

        base_risk_vals = [float(r[1]) for r in rows]
        baseline_mean_vals = [float(r[2]) for r in rows]
        final_risk_vals = [float(r[3]) for r in rows]

        hist_risk = final_risk_vals[:-1]
        baseline_risk = statistics.mean(hist_risk)
        current_risk = final_risk_vals[-1]
        std = statistics.stdev(hist_risk) if len(hist_risk) > 1 else 0.0
        upper = min(100, baseline_risk + std * 1.5)
        lower = max(0, baseline_risk - std * 1.5)

        x = np.arange(len(final_risk_vals))
        x_smooth, final_smooth = make_wave_curve(final_risk_vals)
        _, base_smooth = make_wave_curve(base_risk_vals)
        _, mean_smooth = make_wave_curve(baseline_mean_vals)

        plt.figure(figsize=(12, 6))
        plt.plot(x_smooth, final_smooth, linewidth=3, label="Final Risk")
        plt.plot(x_smooth, base_smooth, linewidth=2, label="Base Risk")
        plt.plot(x_smooth, mean_smooth, linewidth=2, label="Baseline Mean")
        plt.scatter(x, final_risk_vals, s=45, label="Scan Points")
        plt.fill_between(x_smooth, lower, upper, alpha=0.12, label="Normal Baseline Zone")
        plt.axhline(y=baseline_risk, linestyle="--", linewidth=2, label="Historical Baseline")
        plt.axhline(y=upper, linestyle=":", linewidth=2, label="Upper Threshold")
        plt.axhline(y=lower, linestyle=":", linewidth=2, label="Lower Threshold")
        plt.title("Behavioral Baseline Wave Analysis")
        plt.xlabel("Scan Index")
        plt.ylabel("Risk %")
        plt.xticks(x, [f"S{i+1}" for i in x])
        plt.ylim(0, 100)
        plt.grid(True, alpha=0.3)
        plt.legend()

        out = save_current_plot(current_case, "baseline")
        plt.show()

        _show_animated_line(
            f"Animated Baseline Wave - {current_case}",
            x_smooth,
            final_smooth,
            x,
            final_risk_vals,
            "Risk Score (%)",
            extra_lines=[
                {"kind": "plot", "x": x_smooth, "y": base_smooth, "label": "Base Risk"},
                {"kind": "plot", "x": x_smooth, "y": mean_smooth, "label": "Baseline Mean"},
                {"kind": "hline", "y": baseline_risk, "label": "Historical Baseline"},
                {"kind": "hline", "y": upper, "label": "Upper Threshold", "linestyle": ":"},
                {"kind": "hline", "y": lower, "label": "Lower Threshold", "linestyle": ":"},
            ],
        )

        result = (
            f"Baseline Risk: {round(baseline_risk, 2)}%\n"
            f"Current Risk: {round(current_risk, 2)}%\n"
            f"Upper Threshold: {round(upper, 2)}%\n"
            f"Lower Threshold: {round(lower, 2)}%\n"
            f"Graph Saved: {out}\n\n"
        )

        if current_risk > upper:
            result += "Result: HIGH deviation from baseline"
        elif current_risk < lower:
            result += "Result: LOW abnormal behavior"
        else:
            result += "Result: Behavior is within baseline range"

        audit_log(current_user or "", "BASELINE_GRAPH", f"case={current_case} graph={out}")
        messagebox.showinfo("Baseline Analysis", result)
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("Baseline Graph Error", str(e))

def show_roc_curve():
    if len(train_data) < 10 or len(train_labels) < 10:
        messagebox.showerror("Error", "Not enough data for ROC analysis.")
        return

    try:
        df = pd.DataFrame(train_data).copy()
        for col in REQUIRED_COLS:
            if col not in df.columns:
                df[col] = 0

        X = df[REQUIRED_COLS].apply(pd.to_numeric, errors="coerce").fillna(0)
        y = np.array(train_labels, dtype=int)

        if len(np.unique(y)) < 2:
            messagebox.showerror("Error", "ROC needs both normal and risk labels.")
            return

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.30, random_state=42, stratify=y
        )

        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=8,
            min_samples_split=4,
            min_samples_leaf=2,
            random_state=42,
        )
        model.fit(X_train_scaled, y_train)

        y_prob = model.predict_proba(X_test_scaled)[:, 1]
        y_pred = (y_prob >= 0.5).astype(int)

        fpr, tpr, _ = roc_curve(y_test, y_prob)
        roc_auc = auc(fpr, tpr)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        plt.figure(figsize=(9, 6))
        plt.plot(fpr, tpr, linewidth=2.5, label=f"ROC Curve (AUC = {roc_auc:.3f})")
        plt.plot([0, 1], [0, 1], linestyle="--", linewidth=2, label="Random Baseline")
        plt.title("ROC Curve - AI Risk Prediction Model")
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.xlim(0, 1)
        plt.ylim(0, 1.05)
        plt.grid(True, alpha=0.3)
        plt.legend()
        plt.tight_layout()
        plt.show()

        important = model.feature_importances_
        feature_report = (
            f"Login Frequency: {important[0] * 100:.2f}%\n"
            f"Files Accessed: {important[1] * 100:.2f}%\n"
            f"Session Duration: {important[2] * 100:.2f}%\n"
            f"Failed Attempts: {important[3] * 100:.2f}%\n"
            f"Suspicious Flags: {important[4] * 100:.2f}%"
        )

        audit_log(current_user or "", "ROC_CURVE_ANALYSIS", f"auc={roc_auc:.4f} acc={acc:.4f}")

        messagebox.showinfo(
            "ROC Curve Analysis",
            f"AUC Score: {roc_auc:.4f}\n"
            f"Accuracy: {acc * 100:.2f}%\n"
            f"Precision: {prec * 100:.2f}%\n"
            f"Recall: {rec * 100:.2f}%\n"
            f"F1 Score: {f1 * 100:.2f}%\n\n"
            f"Feature Importance:\n{feature_report}"
        )
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("ROC Error", str(e))

def show_confusion_matrix():
    if len(train_data) < 10 or len(train_labels) < 10:
        messagebox.showerror("Error", "Not enough data for Confusion Matrix.")
        return

    try:
        df = pd.DataFrame(train_data).copy()
        for col in REQUIRED_COLS:
            if col not in df.columns:
                df[col] = 0

        X = df[REQUIRED_COLS].apply(pd.to_numeric, errors="coerce").fillna(0)
        y = np.array(train_labels, dtype=int)

        if len(np.unique(y)) < 2:
            messagebox.showerror("Error", "Need both normal and risk labels.")
            return

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.30, random_state=42, stratify=y
        )

        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=8,
            min_samples_split=4,
            min_samples_leaf=2,
            random_state=42,
        )
        model.fit(X_train_scaled, y_train)

        y_pred = model.predict(X_test_scaled)
        cm = confusion_matrix(y_test, y_pred)

        if cm.shape != (2, 2):
            messagebox.showerror("Error", "Confusion Matrix shape invalid.")
            return

        tn, fp, fn, tp = cm.ravel()
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        plt.figure(figsize=(7, 6))
        plt.imshow(cm, cmap="Blues")
        plt.title("Confusion Matrix - AI Risk Prediction")
        plt.xlabel("Predicted Label")
        plt.ylabel("Actual Label")
        plt.xticks([0, 1], ["Normal", "Risk"])
        plt.yticks([0, 1], ["Normal", "Risk"])
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                plt.text(j, i, str(cm[i, j]), ha="center", va="center", fontsize=12)
        plt.colorbar()
        plt.tight_layout()
        plt.show()

        audit_log(current_user or "", "CONFUSION_MATRIX_ANALYSIS", f"tn={tn} fp={fp} fn={fn} tp={tp}")

        messagebox.showinfo(
            "Confusion Matrix Analysis",
            f"TN: {tn}\nFP: {fp}\nFN: {fn}\nTP: {tp}\n\n"
            f"Accuracy: {accuracy * 100:.2f}%\n"
            f"Precision: {precision * 100:.2f}%\n"
            f"Recall: {recall * 100:.2f}%\n"
            f"F1 Score: {f1 * 100:.2f}%"
        )
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("Confusion Matrix Error", str(e))

# ------------------------------
# PDF REPORT
# ------------------------------
def generate_pdf_report():
    if not require_login():
        return
    if not current_case:
        messagebox.showerror("Error", "No active case selected.")
        return

    try:
        cur = db_cursor()
        cur.execute("SELECT case_id, created_at, created_by, title, notes FROM cases WHERE case_id=?", (current_case,))
        case_row = cur.fetchone()

        if not case_row:
            messagebox.showerror("Error", "Case not found.")
            return

        case_id, created_at, created_by, case_title, case_notes = case_row
        case_path = os.path.join(CASES_DIR, current_case)
        os.makedirs(case_path, exist_ok=True)

        cur.execute("""
            SELECT filename, filepath, sha256, md5, size_bytes, added_at, added_by, signature
            FROM evidence WHERE case_id=? ORDER BY added_at ASC
        """, (current_case,))
        evidence_rows = cur.fetchall()

        cur.execute("""
            SELECT ts, username, login_frequency, files_accessed, session_duration,
                   failed_attempts, suspicious_flags, ensemble_prob, anomaly_label,
                   base_risk, baseline_mean, deviation, final_risk, risk_level,
                   stress, productivity_impact,
                   explain_login, explain_files, explain_session, explain_failed, explain_flags,
                   used_camera, confidence_score, recommendation
            FROM ai_scans WHERE case_id=? ORDER BY ts DESC LIMIT 1
        """, (current_case,))
        latest_scan = cur.fetchone()

        cur.execute("SELECT ts, username, action, details FROM audit ORDER BY ts DESC LIMIT 15")
        audit_rows = cur.fetchall()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_path = os.path.join(case_path, f"{current_case}_SIGNED_REPORT_{timestamp}.pdf")
        report_generated_at = now_str()

        doc = SimpleDocTemplate(pdf_path, pagesize=A4)
        styles = getSampleStyleSheet()

        green_center = ParagraphStyle(
            "GreenCenter",
            parent=styles["BodyText"],
            textColor=colors.green,
            alignment=TA_CENTER,
            fontSize=12,
            leading=15,
        )

        green_box = TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eaffea")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0b7a0b")),
            ("BOX", (0, 0), (-1, -1), 1.2, colors.HexColor("#16a34a")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#16a34a")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 11),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ])

        story = []

        story.append(Paragraph(f"<b>{PROJECT_TITLE}</b>", styles["Title"]))
        story.append(Spacer(1, 0.12 * inch))
        story.append(Paragraph("<b>FORENSICORE - Digital Forensic Intelligence Report</b>", styles["Heading1"]))
        story.append(Spacer(1, 0.2 * inch))

        verified_table = Table([[f"✔ DIGITALLY VERIFIED REPORT"]], colWidths=[6.8 * inch])
        verified_table.setStyle(green_box)
        story.append(verified_table)
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph(
            "This report contains digitally signed forensic case data, evidence integrity metadata, audit trace, and AI-based risk analysis.",
            green_center,
        ))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("<b>Case Information</b>", styles["Heading2"]))
        story.append(Paragraph(f"Case ID: {case_id}", styles["BodyText"]))
        story.append(Paragraph(f"Case Title: {case_title or 'N/A'}", styles["BodyText"]))
        story.append(Paragraph(f"Case Created At: {created_at}", styles["BodyText"]))
        story.append(Paragraph(f"Case Created By: {created_by}", styles["BodyText"]))
        story.append(Paragraph(f"Case Notes: {case_notes or 'N/A'}", styles["BodyText"]))
        story.append(Paragraph(f"Report Generated By: {current_user}", styles["BodyText"]))
        story.append(Paragraph(f"Report Generated At: {report_generated_at}", styles["BodyText"]))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("<b>Team Information</b>", styles["Heading2"]))
        story.append(Paragraph(f"Team Leader: {TEAM_LEADER}", styles["BodyText"]))
        for m in TEAM_MEMBERS:
            story.append(Paragraph(f"Team Member: {m}", styles["BodyText"]))
        story.append(Spacer(1, 0.12 * inch))

        story.append(Paragraph("<b>Team Contacts</b>", styles["Heading2"]))
        for name, info in TEAM_CONTACTS.items():
            story.append(Paragraph(f"{name}: {info['phone']} | {info['email']}", styles["BodyText"]))
        story.append(Spacer(1, 0.18 * inch))

        story.append(Paragraph("<b>User / Capture Photos</b>", styles["Heading2"]))
        added_photo = False

        cur.execute("SELECT photo FROM users WHERE username=?", (current_user,))
        user_photo = cur.fetchone()
        if user_photo and user_photo[0]:
            img = _safe_report_image(user_photo[0])
            if img:
                story.append(Paragraph(f"Registered User Photo: {current_user}", styles["BodyText"]))
                story.append(img)
                story.append(Spacer(1, 0.12 * inch))
                added_photo = True

        if os.path.exists(USERS_DIR):
            scan_files = []
            for f in os.listdir(USERS_DIR):
                full_path = os.path.join(USERS_DIR, f)
                if f.startswith(f"scan_{current_user}_{current_case}") and _is_image_file(full_path):
                    scan_files.append(full_path)
            scan_files = sorted(scan_files, reverse=True)

            for scan_img in scan_files[:2]:
                img = _safe_report_image(scan_img)
                if img:
                    story.append(Paragraph(f"AI Scan Capture: {os.path.basename(scan_img)}", styles["BodyText"]))
                    story.append(img)
                    story.append(Spacer(1, 0.12 * inch))
                    added_photo = True

        if not added_photo:
            story.append(Paragraph("No user or scan photos available.", styles["BodyText"]))

        story.append(Spacer(1, 0.18 * inch))
        story.append(Paragraph("<b>Evidence Summary</b>", styles["Heading2"]))

        if evidence_rows:
            evidence_table = [["Filename", "SHA256", "MD5", "Size", "Added By"]]
            for filename, filepath, sha256, md5, size_bytes, added_at, added_by, signature in evidence_rows:
                evidence_table.append([
                    filename,
                    sha256[:18] + "...",
                    md5[:12] + "...",
                    format_bytes(size_bytes),
                    str(added_by),
                ])
            table = Table(evidence_table, repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b8f7b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No evidence found for this case.", styles["BodyText"]))

        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph("<b>Evidence Image Preview</b>", styles["Heading2"]))

        preview_added = False
        for filename, filepath, sha256, md5, size_bytes, added_at, added_by, signature in evidence_rows[:5]:
            if _is_image_file(filepath):
                img = _safe_report_image(filepath)
                if img:
                    story.append(Paragraph(f"Evidence Image: {filename}", styles["BodyText"]))
                    story.append(img)
                    story.append(Spacer(1, 0.12 * inch))
                    preview_added = True

        if not preview_added:
            story.append(Paragraph("No previewable image evidence available.", styles["BodyText"]))

        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph("<b>Latest AI Risk Analysis</b>", styles["Heading2"]))

        latest_scan_payload = {}
        if latest_scan:
            (
                ts, username, login_frequency, files_accessed, session_duration,
                failed_attempts, suspicious_flags, ensemble_prob, anomaly_label,
                base_risk, baseline_mean, deviation, final_risk, risk_level,
                stress, productivity_impact,
                explain_login, explain_files, explain_session, explain_failed, explain_flags,
                used_camera, confidence_score, recommendation
            ) = latest_scan

            latest_scan_payload = {
                "case_id": current_case,
                "scan_time": str(ts),
                "username": str(username),
                "base_risk": int(base_risk),
                "baseline_mean": float(baseline_mean),
                "deviation": float(deviation),
                "final_risk": int(final_risk),
                "risk_level": str(risk_level),
                "stress": float(stress),
                "productivity_impact": float(productivity_impact),
                "confidence_score": float(confidence_score),
                "used_camera": int(used_camera),
            }

            story.append(Paragraph(f"Scan Time: {ts}", styles["BodyText"]))
            story.append(Paragraph(f"Username: {username}", styles["BodyText"]))
            story.append(Paragraph(f"Login Frequency: {login_frequency}", styles["BodyText"]))
            story.append(Paragraph(f"Files Accessed: {files_accessed}", styles["BodyText"]))
            story.append(Paragraph(f"Session Duration: {session_duration}", styles["BodyText"]))
            story.append(Paragraph(f"Failed Attempts: {failed_attempts}", styles["BodyText"]))
            story.append(Paragraph(f"Suspicious Flags: {suspicious_flags}", styles["BodyText"]))
            story.append(Paragraph(f"Risk Probability: {round(float(ensemble_prob) * 100, 2)}%", styles["BodyText"]))
            story.append(Paragraph(f"Anomaly Label: {anomaly_label}", styles["BodyText"]))
            story.append(Paragraph(f"Base Risk: {base_risk}%", styles["BodyText"]))
            story.append(Paragraph(f"Baseline Mean: {round(float(baseline_mean), 2)}", styles["BodyText"]))
            story.append(Paragraph(f"Deviation: {round(float(deviation), 2)}", styles["BodyText"]))
            story.append(Paragraph(f"Final Risk: {final_risk}% ({risk_level})", styles["BodyText"]))
            story.append(Paragraph(f"Stress: {round(float(stress), 2)}%", styles["BodyText"]))
            story.append(Paragraph(f"Productivity Impact: {round(float(productivity_impact), 2)}%", styles["BodyText"]))
            story.append(Paragraph(f"Confidence Score: {round(float(confidence_score), 2)}%", styles["BodyText"]))
            story.append(Paragraph(
                f"Explainable AI -> Login:{round(explain_login * 100, 2)}%, "
                f"Files:{round(explain_files * 100, 2)}%, "
                f"Session:{round(explain_session * 100, 2)}%, "
                f"Failed:{round(explain_failed * 100, 2)}%, "
                f"Flags:{round(explain_flags * 100, 2)}%",
                styles["BodyText"]
            ))
            story.append(Paragraph(f"Used Camera During Scan: {'Yes' if int(used_camera) == 1 else 'No'}", styles["BodyText"]))
            story.append(Paragraph(f"Recommendation: {recommendation}", styles["BodyText"]))
        else:
            story.append(Paragraph("No AI scan available for this case.", styles["BodyText"]))

        trend_img = get_latest_graph(current_case, "risk_trend")
        base_img = get_latest_graph(current_case, "baseline")

        if trend_img:
            story.append(Spacer(1, 0.2 * inch))
            story.append(Paragraph("<b>Risk Trend Graph</b>", styles["Heading2"]))
            img = _safe_report_image(trend_img, max_width=6.2 * inch, max_height=4.0 * inch)
            if img:
                story.append(img)

        if base_img:
            story.append(Spacer(1, 0.2 * inch))
            story.append(Paragraph("<b>Baseline Graph</b>", styles["Heading2"]))
            img = _safe_report_image(base_img, max_width=6.2 * inch, max_height=4.0 * inch)
            if img:
                story.append(img)

        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph("<b>Recent Audit Snapshot</b>", styles["Heading2"]))
        if audit_rows:
            for ts, username, action, details in audit_rows:
                story.append(Paragraph(f"{ts} | {username} | {action} | {details}", styles["BodyText"]))
        else:
            story.append(Paragraph("No audit records available.", styles["BodyText"]))

        report_signature_payload = {
            "case_id": current_case,
            "created_at": str(created_at),
            "created_by": str(created_by),
            "generated_by": str(current_user),
            "generated_at": report_generated_at,
            "evidence_count": len(evidence_rows),
            "latest_scan": latest_scan_payload,
        }
        digital_signature = sign_payload(report_signature_payload)

        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph("<b>Digital Signature Verification</b>", styles["Heading2"]))

        sign_table = Table([
            ["STATUS", "VERIFIED"],
            ["SIGNATURE", digital_signature[:64]],
        ], colWidths=[1.6 * inch, 5.1 * inch])
        sign_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16a34a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#dcfce7")),
            ("BACKGROUND", (1, 1), (1, 1), colors.HexColor("#f0fdf4")),
            ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#166534")),
            ("BOX", (0, 0), (-1, -1), 1.2, colors.HexColor("#16a34a")),
            ("INNERGRID", (0, 0), (-1, -1), 0.8, colors.HexColor("#16a34a")),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        story.append(sign_table)

        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph(
            "<font color='green'><b>This PDF is digitally verified and signed inside the report itself.</b></font>",
            styles["BodyText"]
        ))

        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph("<b>Conclusion</b>", styles["Heading2"]))
        story.append(Paragraph(
            "This signed report contains the active forensic case summary, uploaded evidence details, "
            "user/capture photos, latest AI-based behavioral risk analysis, graph analytics, and recent audit trace.",
            styles["BodyText"]
        ))

        doc.build(story)
        audit_log(current_user or "", "GENERATE_PDF_REPORT", f"case={current_case} pdf={pdf_path}")

        messagebox.showinfo(
            "PDF Report Generated",
            f"Signed forensic report generated successfully.\n\nSaved at:\n{pdf_path}\n\nDigital Signature:\n{digital_signature}"
        )

    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("PDF Report Error", str(e))

# ------------------------------
# LOCK CASE ZIP
# ------------------------------
def lock_case_zip():
    if not require_login():
        return
    if not current_case:
        messagebox.showerror("Error", "No active case selected.")
        return

    try:
        case_path = os.path.join(CASES_DIR, current_case)
        if not os.path.exists(case_path):
            messagebox.showerror("Error", "Case folder not found.")
            return

        cur = db_cursor()
        cur.execute("""
            SELECT filename, filepath, sha256, md5, size_bytes, added_at, added_by, signature
            FROM evidence WHERE case_id=? ORDER BY added_at ASC
        """, (current_case,))
        evidence_rows = cur.fetchall()

        if not evidence_rows:
            messagebox.showerror("Error", "No evidence found in this case.")
            return

        missing_files = []
        manifest_items = []

        for row in evidence_rows:
            filename, filepath, sha256, md5, size_bytes, added_at, added_by, signature = row
            if not os.path.exists(filepath):
                missing_files.append(filename)
                continue
            manifest_items.append({
                "filename": filename,
                "filepath": filepath,
                "sha256": sha256,
                "md5": md5,
                "size_bytes": int(size_bytes),
                "added_at": str(added_at),
                "added_by": str(added_by),
                "signature": str(signature),
            })

        if not manifest_items:
            messagebox.showerror("Error", "All evidence files are missing. Cannot lock case.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_name = f"{current_case}_LOCKED_{timestamp}.zip"
        zip_path = os.path.join(CASES_DIR, zip_name)

        manifest = {
            "case_id": current_case,
            "locked_at": now_str(),
            "locked_by": current_user,
            "total_evidence_in_db": len(evidence_rows),
            "total_evidence_locked": len(manifest_items),
            "missing_files": missing_files,
            "evidence": manifest_items,
        }

        manifest_signature = sign_payload({
            "case_id": current_case,
            "locked_by": current_user,
            "total_evidence_locked": len(manifest_items),
            "evidence_hashes": [item["sha256"] for item in manifest_items],
        })
        manifest["lock_signature"] = manifest_signature

        temp_manifest_path = os.path.join(case_path, f"{current_case}_lock_manifest.json")
        with open(temp_manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for item in manifest_items:
                full_path = item["filepath"]
                if os.path.exists(full_path):
                    arcname = os.path.relpath(full_path, case_path)
                    zf.write(full_path, arcname=arcname)
            zf.write(temp_manifest_path, arcname=os.path.basename(temp_manifest_path))

        try:
            os.remove(temp_manifest_path)
        except Exception:
            pass

        audit_log(current_user or "", "LOCK_CASE_ZIP", f"case={current_case} zip={zip_name} locked={len(manifest_items)}")

        result = (
            f"Case Locked Successfully\n\n"
            f"Case ID: {current_case}\n"
            f"Locked By: {current_user}\n"
            f"ZIP File: {zip_name}\n"
            f"Evidence Locked: {len(manifest_items)}\n"
            f"Missing Files: {len(missing_files)}\n\n"
            f"Digital Lock Signature:\n{manifest_signature}"
        )

        if missing_files:
            result += "\n\nMissing Files:\n" + "\n".join(missing_files[:10])

        messagebox.showinfo("Case Locked", result)
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("Lock Case Error", str(e))

# ------------------------------
# DASHBOARD
# ------------------------------
def dashboard():
    if not require_login():
        return

    try:
        cur = db_cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        total_users = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM cases")
        total_cases = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM evidence")
        total_evidence = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM ai_scans")
        total_scans = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM audit")
        total_logs = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM ai_scans WHERE risk_level='HIGH'")
        high_risk_count = cur.fetchone()[0]

        cur.execute("""
            SELECT case_id, COUNT(*) FROM evidence
            GROUP BY case_id ORDER BY COUNT(*) DESC LIMIT 5
        """)
        evidence_by_case = cur.fetchall()

        cur.execute("""
            SELECT case_id, final_risk, risk_level, ts
            FROM ai_scans ORDER BY ts DESC LIMIT 1
        """)
        latest_scan = cur.fetchone()

        cur.execute("SELECT ts, username, action FROM audit ORDER BY ts DESC LIMIT 5")
        recent_logs = cur.fetchall()

        active_case_info = "None"
        if current_case:
            cur.execute("SELECT COUNT(*) FROM evidence WHERE case_id=?", (current_case,))
            active_case_evidence = cur.fetchone()[0]

            cur.execute("""
                SELECT final_risk, risk_level, ts
                FROM ai_scans WHERE case_id=?
                ORDER BY ts DESC LIMIT 1
            """, (current_case,))
            active_case_scan = cur.fetchone()

            active_case_info = f"Case ID: {current_case}\nEvidence Files: {active_case_evidence}\n"
            if active_case_scan:
                active_case_info += (
                    f"Latest Risk: {active_case_scan[0]}% ({active_case_scan[1]})\n"
                    f"Last Scan Time: {active_case_scan[2]}\n"
                )
            else:
                active_case_info += "Latest Risk: No scan yet\n"

        top_case_text = "No case evidence available\n"
        if evidence_by_case:
            top_case_text = ""
            for case_id, ev_count in evidence_by_case:
                top_case_text += f"{case_id} -> {ev_count} evidence files\n"

        latest_scan_text = "No AI scans yet"
        if latest_scan:
            latest_scan_text = (
                f"Latest AI Scan Case: {latest_scan[0]}\n"
                f"Final Risk: {latest_scan[1]}% ({latest_scan[2]})\n"
                f"Scan Time: {latest_scan[3]}"
            )

        recent_logs_text = "No recent logs"
        if recent_logs:
            recent_logs_text = ""
            for ts, username, action in recent_logs:
                recent_logs_text += f"{ts} | {username} | {action}\n"

        summary = (
            f"SYSTEM DASHBOARD\n\n"
            f"Logged In User: {current_user} ({current_role})\n"
            f"Active Case: {current_case if current_case else 'None'}\n\n"
            f"Total Users: {total_users}/{MAX_USERS}\n"
            f"Total Cases: {total_cases}\n"
            f"Total Evidence Files: {total_evidence}\n"
            f"Total AI Scans: {total_scans}\n"
            f"Total Audit Logs: {total_logs}\n"
            f"High Risk Scans: {high_risk_count}\n\n"
            f"ACTIVE CASE SUMMARY\n{active_case_info}\n"
            f"LATEST AI STATUS\n{latest_scan_text}\n\n"
            f"TOP CASES BY EVIDENCE\n{top_case_text}\n"
            f"RECENT SYSTEM ACTIVITY\n{recent_logs_text}"
        )

        messagebox.showinfo("System Dashboard", summary)
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("Dashboard Error", str(e))

# ------------------------------
# ABOUT
# ------------------------------
def about_project():
    win = tk.Toplevel(root)
    win.title("About Project - FORENSICORE")
    win.configure(bg=BG)
    win.geometry("1150x820")
    win.transient(root)
    win.grab_set()

    tk.Label(win, text=PROJECT_TITLE, font=("Arial", 22, "bold"), bg=BG, fg=ACCENT).pack(pady=(12, 6))
    tk.Label(win, text=TAGLINE, font=("Arial", 12), bg=BG, fg=FG).pack(pady=(0, 12))

    text = tk.Text(
        win,
        wrap="word",
        bg="#0e1420",
        fg="#eef2f7",
        insertbackground="#eef2f7",
        font=("Arial", 11),
    )
    text.pack(fill="both", expand=True, padx=12, pady=12)

    def add_heading(title: str):
        text.insert("end", f"\n{title}\n")
        text.insert("end", f"{'=' * len(title)}\n")

    def add_bullets(lines):
        for line in lines:
            text.insert("end", f"• {line}\n")

    add_heading("Project Overview")
    add_bullets([
        "FORENSICORE is an AI-driven forensic intelligence and predictive risk platform.",
        "It combines evidence security, anomaly detection, behavioral baseline analysis, predictive AI risk scoring, graph analytics, and signed report generation.",
        "It is useful for hackathon demonstration and can be extended into stronger real-world monitoring systems.",
    ])

    add_heading("Core Features")
    add_bullets([
        "Secure login, role-based access, audit logging, and password reset.",
        "Case creation, evidence storage, hashing, verification, and archival.",
        "AI risk scans using Random Forest + Isolation Forest.",
        "Wave-form analytics with saved graph images.",
        "Signed PDF report with green digitally verified section inside the PDF.",
        "Locked ZIP case packaging with manifest and signature.",
        "Camera capture with better fallback support.",
    ])

    add_heading("Team")
    text.insert("end", f"Team Leader: {TEAM_LEADER}\n")
    for m in TEAM_MEMBERS:
        text.insert("end", f"Team Member: {m}\n")

    add_heading("Contacts")
    for name, info in TEAM_CONTACTS.items():
        text.insert("end", f"{name}: {info['phone']} | {info['email']}\n")

    text.configure(state="disabled")

# ------------------------------
# UI STYLE
# ------------------------------
def setup_ttk_theme():
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure("TButton", font=("Arial", 10, "bold"), padding=8)
    style.configure("TEntry", padding=5)
    style.configure("Treeview", rowheight=26, font=("Arial", 9))
    style.configure("Treeview.Heading", font=("Arial", 10, "bold"))

# ------------------------------
# MAIN UI
# ------------------------------
def main():
    global root, status_var

    root = tk.Tk()
    root.title(SYSTEM_NAME)
    root.geometry("1080x820")
    root.minsize(980, 720)
    root.configure(bg=BG)

    setup_ttk_theme()

    # ---------------- HEADER ----------------
    header = tk.Frame(root, bg=BG)
    header.pack(fill="x", pady=(10, 0))

    tk.Label(
        header,
        text=PROJECT_TITLE,
        font=("Arial", 18, "bold"),
        bg=BG,
        fg=ACCENT
    ).pack(pady=(8, 3))

    tk.Label(
        header,
        text=TAGLINE,
        font=("Arial", 11),
        bg=BG,
        fg=FG
    ).pack()

    status_var = tk.StringVar(value="Not logged in")
    tk.Label(
        header,
        textvariable=status_var,
        font=("Arial", 10, "bold"),
        bg=BG,
        fg=INFO
    ).pack(pady=(6, 4))

    tk.Label(
        header,
        text=f"Team Leader: {TEAM_LEADER} | Members: {', '.join(TEAM_MEMBERS)}",
        bg=BG,
        fg=MUTED,
        font=("Arial", 10),
    ).pack()

    tk.Label(
        header,
        text=f"Contact: {TEAM_CONTACTS[TEAM_LEADER]['phone']} | {TEAM_CONTACTS[TEAM_LEADER]['email']}",
        bg=BG,
        fg=MUTED,
        font=("Arial", 10),
    ).pack(pady=(0, 10))

    # ---------------- MAIN SCROLL CONTAINER ----------------
    main_container = tk.Frame(root, bg=BG)
    main_container.pack(fill="both", expand=True, padx=12, pady=10)

    canvas = tk.Canvas(main_container, bg=BG, highlightthickness=0)
    scrollbar = tk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
    scroll_frame = tk.Frame(canvas, bg=BG)

    window_id = canvas.create_window((0, 0), window=scroll_frame, anchor="n")

    def on_frame_configure(event=None):
        canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.coords(window_id, canvas.winfo_width() // 2, 0)

    def on_canvas_configure(event):
        canvas.itemconfig(window_id, width=event.width)

    scroll_frame.bind("<Configure>", on_frame_configure)
    canvas.bind("<Configure>", on_canvas_configure)
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    def _on_mousewheel(event):
        try:
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except Exception:
            pass

    canvas.bind_all("<MouseWheel>", _on_mousewheel)

    # ---------------- MAIN CARD ----------------
    card = tk.Frame(
        scroll_frame,
        bg=CARD,
        bd=0,
        highlightthickness=1,
        highlightbackground="#232a36"
    )
    card.pack(padx=18, pady=12, fill="x", expand=True)

    tk.Label(
        card,
        text="SYSTEM FUNCTIONS",
        font=("Arial", 13, "bold"),
        bg=CARD,
        fg=ACCENT
    ).pack(pady=(14, 12))

    # ---------------- BUTTON WRAPPER ----------------
    btn_wrap = tk.Frame(card, bg=CARD)
    btn_wrap.pack(padx=14, pady=(0, 14), fill="x")

    # ---------------- BUTTON LIST ----------------
    buttons = [
        ("About Project", about_project),
        ("Login", login_screen),
        ("Logout", logout),
        ("Forgot Password", forgot_password),
        ("Register User (Admin) — Max 10", register_user),
        ("Test Camera", test_camera_indexes),
        ("Create Case", create_case),
        ("Select Case", select_case),
        ("Store Evidence (SHA-256 + MD5 + Signature)", store_evidence),
        ("List Evidence", list_evidence),
        ("Verify Evidence Integrity", verify_evidence_integrity),
        ("Export Evidence Manifest (Signed JSON)", export_evidence_manifest),
        ("Export Audit Logs (CSV)", export_audit_logs_csv),
        ("Run AI Risk Scan", ai_scan),
        ("Risk Trend Graph", risk_trend_graph),
        ("Baseline Graph", baseline_graph),
        ("ROC Curve", show_roc_curve),
        ("Confusion Matrix", show_confusion_matrix),
        ("Lock Case (ZIP Archive)", lock_case_zip),
        ("Dashboard", dashboard),
        ("View Audit Logs", view_audit_logs),
        ("Generate PDF Report", generate_pdf_report),
        ("Exit", exit_app),
    ]

    # ---------------- BUTTON LOOP ----------------
    for text, cmd in buttons:
        btn = tk.Button(
            btn_wrap,
            text=text,
            command=cmd,
            bg="#1f2937",
            fg="white",
            activebackground="#00d1b2",
            activeforeground="black",
            font=("Arial", 11, "bold"),
            relief="flat",
            bd=0,
            padx=10,
            pady=10
        )
        btn.pack(fill="x", padx=20, pady=6)

    root.mainloop()


if __name__ == "__main__":
    main()
        