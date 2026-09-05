"""
RANSENTRY - Behavioral Ransomware Detection & Early Warning System
Developed by: Pathan Basheer Khan & Choppa Haritha

Simulates an endpoint detection and response (EDR) agent that monitors suspicious
filesystem heuristics, calculates a decaying risk score over a sliding time window,
monitors canary decoy files (honeypots), checks threat intel feeds (URLhaus),
and runs a Random Forest classifier to flag early-stage ransomware behavior.
"""

import tkinter as tk
from tkinter import messagebox, filedialog
import ttkbootstrap as tb

# Try importing ScrolledText across different ttkbootstrap releases, fall back to tkinter
try:
    from ttkbootstrap.widgets.scrolled import ScrolledText
except ImportError:
    try:
        from ttkbootstrap.scrolled import ScrolledText
    except ImportError:
        from tkinter.scrolledtext import ScrolledText

def _get_text(widget):
    # ttkbootstrap ScrolledText wraps the Text widget inside a Frame; grab the raw widget if needed
    return widget.text if hasattr(widget, 'text') else widget

# Short alias for ttkbootstrap widget styling
ttk = tb

import threading
import queue
import time
import random
import webbrowser
import hashlib
import collections
import os
import json

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.ticker as ticker

# Optional Watchdog integration for live honeypot directory watching
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

# Requests library used for fetching recent threat feeds from URLhaus
try:
    import requests
    import csv
    import io
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Scikit-learn for machine learning behavioral pattern recognition
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# Resolve base directory (handles running as script or frozen PyInstaller binary)
import sys
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PROJECT_INFO_PATH = os.path.join(BASE_DIR, "Ransom info.html")
HONEYPOT_DIR = os.path.join(BASE_DIR, "honeypot_files")

# Behavioral risk heuristics weighting
# Higher weights represent clear ransomware precursors or active destruction
BEHAVIORAL_RISKS = {
    "Normal_Access": 1,
    "Normal_Modify": 2,
    "Mass_File_Read": 10,       # Rapid enumeration / pre-encryption copying
    "File_Rename_Op": 25,       # Appending extensions like .locked or .crypto
    "Encrypting_Operation": 50, # Rapid high-entropy file overwrites
    "Delete_Backups": 75,       # Anti-recovery action (e.g. vssadmin delete shadows)
    "Security_Disable": 100,    # Terminating AV services or defense evasion
}

ACTION_TYPES = list(BEHAVIORAL_RISKS.keys())
AI_WINDOW_SIZE = 20            # Rolling action window size evaluated by the classifier
AI_SAMPLES_PER_CLASS = 400     # Number of synthetic training sequences per class
AI_ALERT_CONFIDENCE = 0.90     # Cutoff threshold to flag autonomous detection

HONEYPOT_FILES_DATA = {
    "passwords_backup.csv": (
        "Service_Name,Username,Password_Hash,MFA_Status,Last_Rotation\n"
        "AWS_Production_Admin,admin_sys,a94a8fe5ccb19ba61c4c0873d391e987982fbbd3,ENABLED,2025-01-15\n"
        "Corporate_VPN_Gateway,soc_operator,8d969eef6ecad3c29a3a629280e686cf0c3f5d5a,ENABLED,2025-02-01\n"
        "SQL_Master_Cluster,db_root,7c4a8d09ca3762af61e59520943dc26494f8941b,MANDATORY,2025-01-20\n"
        "Domain_Controller_AD,svc_ad_admin,e3b0c44298fc1c149afbf4c8996fb92427ae41e4,ENABLED,2025-01-10\n"
    ),
    "financial_report_2025.html": (
        "<!DOCTYPE html>\n<html>\n<head>\n"
        "<meta charset='utf-8'>\n<title>Q1 2025 Financial Performance Report</title>\n"
        "<style>\n"
        "body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 25px; }\n"
        "h1 { color: #38bdf8; font-size: 22px; border-bottom: 2px solid #334155; padding-bottom: 8px; }\n"
        "table { border-collapse: collapse; width: 100%; margin-top: 15px; background-color: #1e293b; }\n"
        "th, td { border: 1px solid #334155; padding: 10px 14px; text-align: left; }\n"
        "th { background-color: #020617; color: #38bdf8; }\n"
        "tr:nth-child(even) { background-color: #1e293b; }\n"
        "</style>\n</head>\n<body>\n"
        "<h1>Q1 2025 Corporate Financial Performance Report [CONFIDENTIAL]</h1>\n"
        "<p><strong>Classification:</strong> RESTRICTED - HONEYPOT DECOY FINANCIAL AUDIT</p>\n"
        "<table>\n"
        "<tr><th>Division</th><th>Q1 Revenue</th><th>Operating Cost</th><th>Net Profit</th></tr>\n"
        "<tr><td>Enterprise Security Services</td><td>$4,250,000</td><td>$1,800,000</td><td>$2,450,000</td></tr>\n"
        "<tr><td>Cloud Threat Intelligence</td><td>$3,100,000</td><td>$1,200,000</td><td>$1,900,000</td></tr>\n"
        "<tr><td>Incident Response Retainer</td><td>$2,800,000</td><td>$950,000</td><td>$1,850,000</td></tr>\n"
        "</table>\n"
        "</body>\n</html>\n"
    ),
    "employee_records.csv": (
        "Employee_ID,Full_Name,Department,Role_Title,Email_Address,Access_Level\n"
        "EMP-1001,Alexander Vance,Cyber Security,Chief Information Security Officer,a.vance@enterprise.org,Level-5 Admin\n"
        "EMP-1002,Sophia Martinez,SOC Incident Response,Lead Threat Analyst,s.martinez@enterprise.org,Level-4 Analyst\n"
        "EMP-1003,Marcus Chen,Infrastructure,Senior Network Engineer,m.chen@enterprise.org,Level-4 Sysadmin\n"
        "EMP-1004,Emily Watson,Compliance & Audit,Security Auditor,e.watson@enterprise.org,Level-3 Auditor\n"
    ),
    "database_backup.sql": (
        "-- =========================================================\n"
        "-- RANSOMWARE EARLY WARNING SYSTEM - HONEYPOT DECOY SCHEMA\n"
        "-- Database: enterprise_sec_vault\n"
        "-- Dump Date: 2025-02-01\n"
        "-- =========================================================\n\n"
        "CREATE TABLE IF NOT EXISTS system_users (\n"
        "    user_id INT PRIMARY KEY AUTO_INCREMENT,\n"
        "    username VARCHAR(50) NOT NULL,\n"
        "    password_hash VARCHAR(128) NOT NULL,\n"
        "    role VARCHAR(30) DEFAULT 'ANALYST',\n"
        "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n"
        ");\n\n"
        "INSERT INTO system_users (username, password_hash, role) VALUES\n"
        "('admin_root', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'SUPER_ADMIN'),\n"
        "('soc_lead', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'SOC_TIER2'),\n"
        "('backup_service', '86604a84976c703b417c8a417537dd9be7520e03ec84a923594cf543505c866f', 'SERVICE_ACCT');\n"
    ),
    "confidential_contracts.rtf": (
        "{\\rtf1\\ansi\\deff0\n"
        "{\\fonttbl{\\f0\\fnil\\fcharset0 Arial;}}\n"
        "{\\colortbl ;\\red56\\green189\\blue248;\\red239\\green68\\blue68;}\n"
        "\\viewkind4\\uc1\\b\\f0\\fs28 ENTERPRISE SECURITY & DATA PROTECTION AGREEMENT\\b0\\fs20\\par\n"
        "\\par\n"
        "\\b Document Classification:\\b0 CONFIDENTIAL - HONEYPOT DECOY CONTRACT\\par\n"
        "\\b Date:\\b0 February 1, 2025\\par\n"
        "\\par\n"
        "This agreement governs the security posture and endpoint protection services deployed across enterprise endpoints.\\par\n"
        "\\par\n"
        "\\b Section 1: Non-Disclosure & Threat Neutralization\\b0\\par\n"
        "All incident response metrics and behavioral heuristics monitored by the Ransomware Early Warning System (REWS) are cryptographically logged and protected.\\par\n"
        "\\par\n"
        "\\b Section 2: Deception Environment Terms\\b0\\par\n"
        "Interaction with decoy assets triggers automated SOC alerting and endpoint isolation controls.\\par\n"
        "}\n"
    ),
    "passwords_backup.xlsx": (
        "Service_Name\tUsername\tPassword_Hash\tMFA_Status\tLast_Rotation\n"
        "AWS_Production_Admin\tadmin_sys\ta94a8fe5ccb19ba61c4c0873d391e987982fbbd3\tENABLED\t2025-01-15\n"
        "Corporate_VPN_Gateway\tsoc_operator\t8d969eef6ecad3c29a3a629280e686cf0c3f5d5a\tENABLED\t2025-02-01\n"
        "SQL_Master_Cluster\tdb_root\t7c4a8d09ca3762af61e59520943dc26494f8941b\tMANDATORY\t2025-01-20\n"
        "Domain_Controller_AD\tsvc_ad_admin\te3b0c44298fc1c149afbf4c8996fb92427ae41e4\tENABLED\t2025-01-10\n"
    ),
    "financial_report_2025.docx": (
        "{\\rtf1\\ansi\\deff0\n"
        "{\\fonttbl{\\f0\\fnil\\fcharset0 Arial;}}\n"
        "\\viewkind4\\uc1\\b\\f0\\fs26 Q1 2025 CORPORATE FINANCIAL REPORT\\b0\\fs20\\par\n"
        "\\par\n"
        "Revenue Target: $10,150,000 USD\\par\n"
        "Operating Cost: $3,950,000 USD\\par\n"
        "Net Operational Surplus: $6,200,000 USD\\par\n"
        "}\n"
    ),
}

HONEYPOT_FILES = list(HONEYPOT_FILES_DATA.keys())

THREAT_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREAT_FEED_MAX_ROWS = 25

RANSOMWARE_THRESHOLD = 150
TIME_WINDOW = 10       # Seconds before event score decays
GRAPH_POINTS = 100     # Display window on real-time graph
THREAT_LEVEL_MULTIPLIER = 1.0


def set_threshold(value):
    global RANSOMWARE_THRESHOLD
    RANSOMWARE_THRESHOLD = value


def set_time_window(value):
    global TIME_WINDOW
    TIME_WINDOW = value


def set_threat_level_multiplier(value):
    global THREAT_LEVEL_MULTIPLIER
    THREAT_LEVEL_MULTIPLIER = value


def get_effective_threshold():
    return RANSOMWARE_THRESHOLD * THREAT_LEVEL_MULTIPLIER


# Reusable scrollable frame used in the Honeypot file browser and Security Quiz
class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.canvas = tk.Canvas(self, bg="#0f172a", highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_content = ttk.Frame(self.canvas, padding=12)

        self.scrollable_content.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_content, anchor="nw")
        # Keep inner frame matched with canvas width when resized
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.canvas_window, width=e.width))

        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")


# Tamper-evident audit trail using SHA-256 hash chaining.
# Each logged event includes the cryptographic hash of the previous record.
class SecureLogBlock:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}"
        return hashlib.sha256(block_string.encode("utf-8")).hexdigest()


class SecureLog:
    def __init__(self):
        self.chain = []
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = SecureLogBlock(0, time.time(), "GENESIS BLOCK - Log Chain Initialized", "0" * 64)
        self.chain.append(genesis)

    def add_entry(self, data):
        previous_block = self.chain[-1]
        new_block = SecureLogBlock(len(self.chain), time.time(), data, previous_block.hash)
        self.chain.append(new_block)
        return new_block

    def verify_chain(self):
        # Walk through blocks to ensure hashes and sequence links are unbroken
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.compute_hash():
                return False, i
            if current.previous_hash != previous.hash:
                return False, i

        return True, None


# Honeypot decoy files setup. Creates decoy documents in the honeypot_files directory
# so any process trying to modify or encrypt them will trigger watchdog alerts.
def ensure_honeypot_files(force=False):
    if not os.path.exists(HONEYPOT_DIR):
        os.makedirs(HONEYPOT_DIR)

    for filename, content in HONEYPOT_FILES_DATA.items():
        filepath = os.path.join(HONEYPOT_DIR, filename)
        should_write = force or not os.path.exists(filepath)
        if not should_write and os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    first_lines = f.read(150)
                    # Overwrite old basic warning text with richer demo templates
                    if "This is a decoy file created by the Ransomware Early Warning System" in first_lines:
                        should_write = True
            except Exception:
                pass

        if should_write:
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)
            except Exception:
                pass


if WATCHDOG_AVAILABLE:
    # Filesystem watcher to detect unauthorized access to decoy canary files
    class HoneypotEventHandler(FileSystemEventHandler):
        def __init__(self, monitor):
            super().__init__()
            self.monitor = monitor

        def on_created(self, event):
            if not event.is_directory and self.monitor.honeypot_active:
                self.monitor.trigger_honeypot_alert(
                    "Normal_Modify", f"CREATED: {os.path.basename(event.src_path)}")

        def on_modified(self, event):
            # File writes / encryptions on honeypots get flagged as Encrypting_Operation
            if not event.is_directory and self.monitor.honeypot_active:
                self.monitor.trigger_honeypot_alert(
                    "Encrypting_Operation", f"MODIFIED: {os.path.basename(event.src_path)}")

        def on_deleted(self, event):
            # File deletion or shadow-kill attempts
            if not event.is_directory and self.monitor.honeypot_active:
                self.monitor.trigger_honeypot_alert(
                    "Delete_Backups", f"DELETED: {os.path.basename(event.src_path)}")

        def on_moved(self, event):
            # File renaming / extension appending (e.g. .locked)
            if not event.is_directory and self.monitor.honeypot_active:
                self.monitor.trigger_honeypot_alert(
                    "File_Rename_Op",
                    f"RENAMED: {os.path.basename(event.src_path)} -> {os.path.basename(event.dest_path)}")


# Queries the public URLhaus abuse feed for recently reported malicious URLs.
# If recent active ransomware indicators are observed, we lower the threshold to increase alert sensitivity.
def fetch_threat_feed():
    if not REQUESTS_AVAILABLE:
        return False, "The 'requests' library is not installed."

    try:
        response = requests.get(THREAT_FEED_URL, timeout=10)
        response.raise_for_status()
    except Exception as e:
        return False, f"Could not reach threat feed: {e}"

    try:
        # Ignore comments and header markers in the CSV text
        lines = [line for line in response.text.splitlines() if line and not line.startswith("#")]
        reader = csv.reader(lines)
        entries = []
        for row in reader:
            if len(row) < 7:
                continue
            entries.append({
                "date_added": row[1].strip('"'),
                "url": row[2].strip('"'),
                "threat": row[5].strip('"'),
                "tags": row[6].strip('"'),
            })
            if len(entries) >= THREAT_FEED_MAX_ROWS:
                break
        return True, entries
    except Exception as e:
        return False, f"Could not parse threat feed data: {e}"


# Synthetic training data generator for the Random Forest classifier.
# In 'normal' mode, the simulated process does standard file reads and occasional writes.
# In 'malicious' mode, it simulates ransomware stages: recon -> rename -> mass write -> backup wipe.
def generate_synthetic_action_sequence(mode, length, start_counter=1):
    actions = []
    file_counter = start_counter

    for _ in range(length):
        action = "Normal_Access"

        if mode == 'normal':
            if random.random() < 0.15:
                action = random.choice(["Normal_Modify", "Normal_Access"])

        elif mode == 'malicious':
            if random.random() < 0.35:
                if file_counter % 20 == 0 and file_counter > 20:
                    action = "Security_Disable"
                elif file_counter % 15 == 0 and file_counter > 15:
                    action = "Delete_Backups"
                elif file_counter % 5 == 0 and file_counter > 5:
                    action = "Encrypting_Operation"
                elif file_counter % 10 == 0 and file_counter > 10:
                    action = "File_Rename_Op"
                else:
                    action = random.choice(["File_Rename_Op", "Mass_File_Read"])
            else:
                action = random.choice(["Mass_File_Read", "Normal_Access", "Normal_Access"])

        actions.append(action)
        file_counter += 1

    return actions


# Converts a sliding window of actions into a normalized numerical feature vector
# (relative frequencies of each action type + normalized average risk score).
def extract_features(action_window):
    total = len(action_window) if action_window else 1
    counts = {a: 0 for a in ACTION_TYPES}
    for action in action_window:
        if action in counts:
            counts[action] += 1

    features = [counts[a] / total for a in ACTION_TYPES]
    avg_risk = sum(BEHAVIORAL_RISKS.get(a, 0) for a in action_window) / total
    features.append(avg_risk / 100.0)

    return features


# Train a quick Random Forest model using generated synthetic action sequences.
# Returns (success, model_or_error, test_accuracy).
def train_ai_model():
    if not AI_AVAILABLE:
        return False, "scikit-learn is not installed.", None

    try:
        X, y = [], []
        for _ in range(AI_SAMPLES_PER_CLASS):
            start = random.randint(1, 300)
            normal_window = generate_synthetic_action_sequence('normal', AI_WINDOW_SIZE, start)
            X.append(extract_features(normal_window))
            y.append('normal')

            malicious_window = generate_synthetic_action_sequence('malicious', AI_WINDOW_SIZE, start)
            X.append(extract_features(malicious_window))
            y.append('malicious')

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y)

        # 100 trees with max_depth=8 trains in ~100-200ms and avoids overfitting
        model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
        model.fit(X_train, y_train)

        predictions = model.predict(X_test)
        accuracy = accuracy_score(y_test, predictions)

        return True, model, accuracy
    except Exception as e:
        return False, f"AI training failed: {e}", None


# Central monitoring engine. Tracks active risk score, manages the decay worker,
# dispatches honeypot alerts, and computes real-time threat predictions.
class RansomwareMonitor:
    def __init__(self):
        self.risk_queue = queue.Queue()
        self.event_log = queue.Queue()
        self.is_running = False
        self.current_mode = None
        self.decay_running = False
        self.current_risk_score = 0
        self.risk_history = []
        self.graph_data = collections.deque(maxlen=GRAPH_POINTS)

        self.simulation_thread = None
        self.decay_thread = None
        self.risk_lock = threading.Lock()

        self.secure_log = SecureLog()
        self.honeypot_observer = None
        self.honeypot_active = False

        self.threat_feed_queue = queue.Queue()

        self.recent_actions = collections.deque(maxlen=AI_WINDOW_SIZE)
        self.ai_model = None
        self.ai_trained = False
        self.ai_confidence = 0.0
        self.ai_status_queue = queue.Queue()

        # Warm up AI model in background so the confidence meter is active from launch
        if AI_AVAILABLE:
            self.train_ai_model_async()

    def _ensure_decay_running(self):
        if not self.decay_running:
            self.decay_running = True
            self.decay_thread = threading.Thread(target=self._decay_worker, daemon=True)
            self.decay_thread.start()

    def start_simulation(self, mode):
        already_running = self.is_running

        if already_running:
            if mode == self.current_mode:
                return

            self.is_running = False
            if self.simulation_thread and self.simulation_thread.is_alive():
                self.simulation_thread.join(timeout=1.0)

        self.is_running = True
        self.current_mode = mode

        # Lazy model training if it hasn't completed yet
        if AI_AVAILABLE and not self.ai_trained:
            self.train_ai_model_async()

        if not already_running:
            with self.risk_lock:
                self.current_risk_score = 0
                self.risk_history = []
                self.graph_data.clear()

            while not self.event_log.empty():
                self.event_log.get()
            while not self.risk_queue.empty():
                self.risk_queue.get()

        self.simulation_thread = threading.Thread(target=self._simulate_worker, args=(mode,), daemon=True)
        self.simulation_thread.start()
        self._ensure_decay_running()

        if already_running:
            self.event_log.put((f"--- Switched to {mode.upper()} Mode ---", "status"))
            self.secure_log.add_entry(f"Switched to {mode.upper()} Mode")
        else:
            self.event_log.put((f"--- Simulation Started: {mode.upper()} Mode ---", "status"))
            self.secure_log.add_entry(f"Simulation Started: {mode.upper()} Mode")

    def stop_simulation(self):
        if self.is_running:
            self.is_running = False
            self.current_mode = None
            self.event_log.put(("--- Simulation Stopped (decaying active risk) ---", "status"))
            self.secure_log.add_entry("Simulation Stopped")

    def _simulate_worker(self, mode):
        # Event generator simulating endpoint file system calls
        file_counter = 1

        while self.is_running:
            action = "Normal_Access"
            risk = BEHAVIORAL_RISKS[action]

            if mode == 'normal':
                if random.random() < 0.15:
                    action = random.choice(["Normal_Modify", "Normal_Access"])
                    risk = BEHAVIORAL_RISKS[action]

            elif mode == 'malicious':
                # Replicate ransomware lifecycle: enumeration -> encryption -> shadow copy wipe -> AV disable
                if random.random() < 0.35:
                    if file_counter % 20 == 0 and file_counter > 20:
                        action = "Security_Disable"
                    elif file_counter % 15 == 0 and file_counter > 15:
                        action = "Delete_Backups"
                    elif file_counter % 5 == 0 and file_counter > 5:
                        action = "Encrypting_Operation"
                    elif file_counter % 10 == 0 and file_counter > 10:
                        action = "File_Rename_Op"
                    else:
                        action = random.choice(["File_Rename_Op", "Mass_File_Read"])
                    risk = BEHAVIORAL_RISKS[action]
                else:
                    action = random.choice(["Mass_File_Read", "Normal_Access", "Normal_Access"])
                    risk = BEHAVIORAL_RISKS[action]

            event_name = f"Process_XYZ accessing file_{file_counter}.txt"

            self.event_log.put((event_name, action))
            self.risk_queue.put(risk)
            self.secure_log.add_entry(f"{event_name} - {action} (risk={risk})")

            self.recent_actions.append(action)
            self._update_ai_confidence()

            file_counter += 1
            time.sleep(random.uniform(0.1, 0.35))

    def _decay_worker(self):
        # Background risk decay: events older than TIME_WINDOW seconds are expired
        decay_counter = 0
        while self.decay_running:
            decay_counter += 1
            while not self.risk_queue.empty():
                new_risk = self.risk_queue.get()
                current_time = time.time()
                with self.risk_lock:
                    self.risk_history.append((current_time, new_risk))
                    self.current_risk_score += new_risk

            current_time = time.time()
            decay_amount = 0
            new_history = []

            with self.risk_lock:
                for timestamp, risk in self.risk_history:
                    if current_time - timestamp > TIME_WINDOW:
                        decay_amount += risk
                    else:
                        new_history.append((timestamp, risk))

                self.risk_history = new_history
                self.current_risk_score -= decay_amount
                self.current_risk_score = max(0, self.current_risk_score)
                self.graph_data.append(self.current_risk_score)

            # Smoothly cool down AI confidence when simulation stops
            if not self.is_running:
                if self.recent_actions:
                    if decay_counter % 2 == 0:
                        self.recent_actions.popleft()
                        self._update_ai_confidence()
                else:
                    if self.ai_confidence > 0:
                        self.ai_confidence = max(0.0, self.ai_confidence - 0.05)

            time.sleep(0.2)

    def start_honeypot(self):
        if not WATCHDOG_AVAILABLE:
            self.event_log.put(("Honeypot unavailable: missing 'watchdog' package", "status"))
            return False
        if self.honeypot_active:
            return True

        if not os.path.exists(HONEYPOT_DIR):
            os.makedirs(HONEYPOT_DIR)
        self.honeypot_observer = Observer()
        handler = HoneypotEventHandler(self)
        self.honeypot_observer.schedule(handler, HONEYPOT_DIR, recursive=False)
        self.honeypot_observer.start()
        self.honeypot_active = True

        self.event_log.put((f"--- Honeypot Monitoring ACTIVE ({HONEYPOT_DIR}) ---", "status"))
        self.secure_log.add_entry(f"Honeypot Monitoring Enabled ({HONEYPOT_DIR})")
        return True

    def stop_honeypot(self):
        if self.honeypot_active and self.honeypot_observer:
            self.honeypot_observer.stop()
            self.honeypot_observer.join(timeout=2)
            self.honeypot_active = False
            self.event_log.put(("--- Honeypot Monitoring DISABLED ---", "status"))
            self.secure_log.add_entry("Honeypot Monitoring Disabled")

    def trigger_honeypot_alert(self, action, detail):
        risk = BEHAVIORAL_RISKS[action]
        event_name = f"HONEYPOT ALERT: {detail}"

        self._ensure_decay_running()

        current_time = time.time()
        with self.risk_lock:
            self.risk_history.append((current_time, risk))
            self.current_risk_score += risk

        self.event_log.put((event_name, action))
        self.secure_log.add_entry(f"{event_name} (risk={risk})")

        self.recent_actions.append(action)
        self._update_ai_confidence()

    def fetch_threat_feed_async(self):
        threading.Thread(target=self._threat_feed_worker, daemon=True).start()

    def _threat_feed_worker(self):
        success, result = fetch_threat_feed()
        ransomware_count = 0
        multiplier = THREAT_LEVEL_MULTIPLIER

        if success:
            for entry in result:
                combined = f"{entry['threat']} {entry['tags']}".lower()
                if "ransom" in combined:
                    ransomware_count += 1

            # Adjust threshold sensitivity if active ransomware campaigns are circulating
            if ransomware_count >= 5:
                multiplier = 0.7
            elif ransomware_count >= 1:
                multiplier = 0.85
            else:
                multiplier = 1.0

            set_threat_level_multiplier(multiplier)
            self.secure_log.add_entry(
                f"Threat feed refreshed: {len(result)} indicators, {ransomware_count} ransomware-tagged, multiplier={multiplier}")
        else:
            self.secure_log.add_entry(f"Threat feed refresh failed: {result}")

        self.threat_feed_queue.put((success, result, ransomware_count, multiplier))

    def train_ai_model_async(self):
        threading.Thread(target=self._train_ai_worker, daemon=True).start()

    def _train_ai_worker(self):
        success, model_or_error, accuracy = train_ai_model()

        if success:
            self.ai_model = model_or_error
            self.ai_trained = True
            self.secure_log.add_entry(f"AI model trained: {accuracy * 100:.1f}% accuracy")
        else:
            self.secure_log.add_entry(f"AI model training failed: {model_or_error}")

        self.ai_status_queue.put((success, model_or_error, accuracy))

    def _update_ai_confidence(self):
        recent = list(self.recent_actions) if self.recent_actions else []

        if self.ai_trained and len(recent) >= 3:
            features = extract_features(recent)
            try:
                probabilities = self.ai_model.predict_proba([features])[0]
                malicious_index = list(self.ai_model.classes_).index('malicious')
                self.ai_confidence = probabilities[malicious_index]
                return
            except Exception:
                pass

        # Heuristic fallback if model isn't trained yet or window is warming up
        if not recent:
            self.ai_confidence = 0.0
        else:
            high_risk_count = sum(1 for a in recent if a in ("Encrypting_Operation", "Delete_Backups", "Security_Disable", "File_Rename_Op"))
            ratio = high_risk_count / len(recent)
            self.ai_confidence = min(0.99, max(0.0, ratio * 1.8))


# Dashboard interface using ttkbootstrap darkly theme
class WarningSystemGUI(tb.Window):
    def __init__(self, monitor):
        super().__init__(themename="darkly")
        self.title("RANSENTRY | Ransomware Early Warning System & Threat Intelligence Console")
        self.geometry("1260x840")
        self.minsize(1080, 740)

        # Set application window icon (.ico on Windows, PNG fallback)
        logo_ico = os.path.join(BASE_DIR, "ransentry_icon.ico")
        logo_png = os.path.join(BASE_DIR, "ransentry_logo.png")

        if os.path.exists(logo_ico):
            try:
                self.iconbitmap(logo_ico)
            except Exception:
                pass

        if os.path.exists(logo_png):
            try:
                from PIL import Image, ImageTk
                icon_img = Image.open(logo_png)
                self._app_icon_tk = ImageTk.PhotoImage(icon_img)
                self.iconphoto(False, self._app_icon_tk)
            except Exception:
                pass

        self.monitor = monitor

        # Dashboard palette
        self.COLOR_BG = '#0f172a'        # Slate 900
        self.COLOR_CARD = '#1e293b'      # Slate 800
        self.COLOR_CARD_BORDER = '#334155' # Slate 700
        self.COLOR_CYAN = '#38bdf8'      # Sky 400
        self.COLOR_GREEN = '#10b981'     # Emerald 500
        self.COLOR_AMBER = '#f59e0b'     # Amber 500
        self.COLOR_RED = '#ef4444'       # Red 500
        self.COLOR_TEXT_MUTED = '#94a3b8' # Slate 400

        # Setup Matplotlib Figure with dark slate palette
        self.fig, self.ax = plt.subplots(figsize=(8, 3.2), facecolor=self.COLOR_CARD)
        self.line, = self.ax.plot([], [], color=self.COLOR_CYAN, linewidth=2.5, label='Risk Score')
        self.fill_poly = None

        self.create_widgets()
        self.setup_graph()
        self.update_gui()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        try:
            self.monitor.stop_honeypot()
            self.monitor.stop_simulation()
            self.monitor.decay_running = False
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass

    def show_project_info(self):
        try:
            webbrowser.open(PROJECT_INFO_PATH)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open project documentation: {e}")

    def export_log(self):
        content = _get_text(self.log_text).get("1.0", "end").strip()
        if not content:
            messagebox.showinfo("Export Log", "Activity log is empty.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile="rews_activity_log.txt",
            title="Export Activity Log"
        )
        if filepath:
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Export Log", f"Log successfully exported to:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not export log: {e}")

    def export_incident_report(self):
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        is_valid, broken_idx = self.monitor.secure_log.verify_chain()
        effective = get_effective_threshold()
        score = self.monitor.current_risk_score

        if score >= effective:
            status = "CRITICAL ALERT: RANSOMWARE ATTACK IN PROGRESS"
        elif score >= effective * 0.5:
            status = "HIGH RISK WARNING"
        else:
            status = "SYSTEM NORMAL / SAFE"
        ai_sec = f"Trained ({self.monitor.ai_confidence * 100:.1f}% Threat Probability)" if (AI_AVAILABLE and self.monitor.ai_trained) else f"Active ({self.monitor.ai_confidence * 100:.1f}% Threat Probability)"
        honeypot_sec = "ACTIVE (Monitoring Decoys)" if self.monitor.honeypot_active else "Disabled"

        report = f"""================================================================================
RANSENTRY - RANSOMWARE EARLY WARNING SYSTEM (REWS) - SOC INCIDENT REPORT
================================================================================
Timestamp               : {now_str}
Security Audit Hash     : {self.monitor.secure_log.chain[-1].hash[:32]}...
--------------------------------------------------------------------------------
1. CURRENT DEFENSE & THREAT METRICS
   - Threat Level Status        : {status}
   - Behavioral Risk Score      : {score} pts
   - Effective Alert Threshold  : {effective:.0f} pts (Multiplier: {THREAT_LEVEL_MULTIPLIER})
   - Decay Window               : {TIME_WINDOW} seconds
   - AI Detection Engine        : {ai_sec}
   - Honeypot Monitor          : {honeypot_sec}
   - Hash Chain Integrity       : {"VALID" if is_valid else f"CORRUPTED (Block {broken_idx})"}

2. RECENT EVENT AUDIT TRAIL
--------------------------------------------------------------------------------
"""
        report += _get_text(self.log_text).get("1.0", "end").strip()
        report += "\n================================================================================\nEND OF REPORT\n"

        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Security Incident Report", "*.txt"), ("All Files", "*.*")],
            initialfile=f"REWS_Incident_Report_{int(time.time())}.txt",
            title="Export Incident Audit Report"
        )
        if filepath:
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(report)
                messagebox.showinfo("Report Exported", f"Incident report exported:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {e}")

    def create_widgets(self):
        # Top application menu
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Activity Log", command=self.export_log)
        file_menu.add_command(label="Export Incident Report", command=self.export_incident_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Project Info", command=self.show_project_info)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.configure(menu=menubar)

        # Main window layout wrapper
        root_container = ttk.Frame(self, padding=(16, 12))
        root_container.pack(fill="both", expand=True)

        # Header banner with branding and quick-action export buttons
        header_frame = ttk.Frame(root_container)
        header_frame.pack(fill="x", pady=(0, 12))

        header_left = ttk.Frame(header_frame)
        header_left.pack(side="left")

        logo_png = os.path.join(BASE_DIR, "ransentry_logo.png")
        if os.path.exists(logo_png):
            try:
                from PIL import Image, ImageTk
                img = Image.open(logo_png).resize((115, 92), Image.Resampling.LANCZOS)
                self.header_logo_img = ImageTk.PhotoImage(img)
                logo_lbl = ttk.Label(header_left, image=self.header_logo_img)
                logo_lbl.pack(side="left", padx=(0, 16))
            except Exception:
                pass

        header_text_frame = ttk.Frame(header_left)
        header_text_frame.pack(side="left")

        title_lbl = ttk.Label(
            header_text_frame, 
            text="RANSENTRY", 
            font=("Helvetica", 24, "bold"),
            bootstyle="light"
        )
        title_lbl.pack(anchor="w")

        subtitle_lbl = ttk.Label(
            header_text_frame, 
            text="Ransomware Early Warning System | See Threats. Stop Damage. Stay Secure.", 
            font=("Helvetica", 10, "bold"),
            bootstyle="info"
        )
        subtitle_lbl.pack(anchor="w", pady=(2, 0))

        header_right = ttk.Frame(header_frame)
        header_right.pack(side="right")

        ttk.Button(
            header_right, 
            text="Export Report", 
            command=self.export_incident_report,
            bootstyle="success-outline"
        ).pack(side="left", padx=5)

        ttk.Button(
            header_right, 
            text="Project Info", 
            command=self.show_project_info,
            bootstyle="info-outline"
        ).pack(side="left", padx=5)

        # Primary navigation notebook
        self.notebook = ttk.Notebook(root_container, bootstyle="dark")
        self.notebook.pack(fill="both", expand=True)

        dashboard_tab = ttk.Frame(self.notebook, padding=12)
        ai_tab = ttk.Frame(self.notebook, padding=20)
        honeypot_tab = ttk.Frame(self.notebook, padding=20)
        blockchain_tab = ttk.Frame(self.notebook, padding=20)
        threat_feed_tab = ttk.Frame(self.notebook, padding=20)
        awareness_tab = ttk.Frame(self.notebook, padding=12)
        settings_tab = ttk.Frame(self.notebook, padding=20)

        self.notebook.add(dashboard_tab, text="  Dashboard  ")
        self.notebook.add(honeypot_tab, text="  Honeypot Deception  ")
        self.notebook.add(blockchain_tab, text="  Hash-Chain Log  ")
        self.notebook.add(threat_feed_tab, text="  Threat Intel Feed  ")
        self.notebook.add(ai_tab, text="  AI Pattern Detection  ")
        self.notebook.add(settings_tab, text="  Detection Config  ")
        self.notebook.add(awareness_tab, text="  SOC & Awareness  ")

        self.build_dashboard_tab(dashboard_tab)
        self.build_honeypot_tab(honeypot_tab)
        self.build_blockchain_tab(blockchain_tab)
        self.build_threat_feed_tab(threat_feed_tab)
        self.build_ai_tab(ai_tab)
        self.build_settings_tab(settings_tab)
        self.build_awareness_tab(awareness_tab)

        def on_main_tab_change(event):
            try:
                selected_text = self.notebook.tab(self.notebook.select(), "text")
                if "SOC & Awareness" in selected_text:
                    if hasattr(self, 'awareness_nb'):
                        sub_text = self.awareness_nb.tab(self.awareness_nb.select(), "text")
                        if "Dynamic Security Quiz" in sub_text:
                            self.load_random_quiz()
            except Exception:
                pass

        self.notebook.bind("<<NotebookTabChanged>>", on_main_tab_change)

    # Main dashboard view: KPI cards, real-time risk chart, simulation controls, and terminal stream
    def build_dashboard_tab(self, parent):
        # Row 1: Top KPI metrics cards
        kpi_grid = ttk.Frame(parent)
        kpi_grid.pack(fill="x", pady=(0, 12))

        # Card: Current alert state and point score
        card1 = ttk.LabelFrame(kpi_grid, text=" Live Threat Level ")
        card1.pack(side="left", fill="both", expand=True, padx=(0, 6))

        card1_inner = ttk.Frame(card1, padding=10)
        card1_inner.pack(fill="both", expand=True)

        self.status_badge = ttk.Label(
            card1_inner, 
            text="SAFE", 
            font=("Helvetica", 14, "bold"), 
            anchor="center",
            bootstyle="success-inverse"
        )
        self.status_badge.pack(fill="x", pady=(0, 6))

        score_sub = ttk.Frame(card1_inner)
        score_sub.pack(anchor="center")

        ttk.Label(score_sub, text="Score: ", font=("Helvetica", 10), bootstyle="secondary").pack(side="left")
        self.score_value_label = ttk.Label(score_sub, text="0", font=("Helvetica", 16, "bold"), bootstyle="light")
        self.score_value_label.pack(side="left")

        # Card: Threshold and sensitivity multiplier (adjusted by threat feed)
        card2 = ttk.LabelFrame(kpi_grid, text=" Threshold & Sensitivity ")
        card2.pack(side="left", fill="both", expand=True, padx=6)

        card2_inner = ttk.Frame(card2, padding=10)
        card2_inner.pack(fill="both", expand=True)

        self.threshold_display_label = ttk.Label(
            card2_inner, 
            text=f"{RANSOMWARE_THRESHOLD} pts", 
            font=("Helvetica", 16, "bold"), 
            bootstyle="info"
        )
        self.threshold_display_label.pack(anchor="w")

        self.sensitivity_label = ttk.Label(
            card2_inner, 
            text="Threat Multiplier: 1.0x (Normal)", 
            font=("Helvetica", 9), 
            bootstyle="secondary"
        )
        self.sensitivity_label.pack(anchor="w", pady=(4, 0))

        # Card: AI classifier confidence readout
        card3 = ttk.LabelFrame(kpi_grid, text=" AI Pattern Confidence ")
        card3.pack(side="left", fill="both", expand=True, padx=6)

        card3_inner = ttk.Frame(card3, padding=10)
        card3_inner.pack(fill="both", expand=True)

        self.kpi_ai_confidence_lbl = ttk.Label(
            card3_inner, 
            text="0.0% Ransomware", 
            font=("Helvetica", 14, "bold"), 
            bootstyle="success"
        )
        self.kpi_ai_confidence_lbl.pack(anchor="w")

        self.kpi_ai_status_lbl = ttk.Label(
            card3_inner, 
            text="Model: Initializing...", 
            font=("Helvetica", 9), 
            bootstyle="secondary"
        )
        self.kpi_ai_status_lbl.pack(anchor="w", pady=(4, 0))

        # Card: Honeypot canary and log audit status
        card4 = ttk.LabelFrame(kpi_grid, text=" Active Defense Engines ")
        card4.pack(side="left", fill="both", expand=True, padx=(6, 0))

        card4_inner = ttk.Frame(card4, padding=10)
        card4_inner.pack(fill="both", expand=True)

        self.kpi_honeypot_lbl = ttk.Label(
            card4_inner, 
            text="Honeypot: Inactive", 
            font=("Helvetica", 10, "bold"), 
            bootstyle="secondary"
        )
        self.kpi_honeypot_lbl.pack(anchor="w")

        self.kpi_blockchain_lbl = ttk.Label(
            card4_inner, 
            text="Hash-Chain: Intact", 
            font=("Helvetica", 10, "bold"), 
            bootstyle="success"
        )
        self.kpi_blockchain_lbl.pack(anchor="w", pady=(4, 0))

        # Row 2: Attack simulation triggers on left, real-time risk plot on right
        middle_row = ttk.Frame(parent)
        middle_row.pack(fill="both", expand=True, pady=(0, 10))

        ctrl_panel = ttk.LabelFrame(middle_row, text=" Threat Simulator Controls ")
        ctrl_panel.pack(side="left", fill="y", padx=(0, 10))

        ctrl_inner = ttk.Frame(ctrl_panel, padding=12)
        ctrl_inner.pack(fill="both", expand=True)

        ttk.Label(
            ctrl_inner, 
            text="Select Event Generator:", 
            font=("Helvetica", 9, "bold"),
            bootstyle="secondary"
        ).pack(anchor="w", pady=(0, 8))

        ttk.Button(
            ctrl_inner, 
            text="Start Normal Activity", 
            command=lambda: self.start(mode='normal'), 
            bootstyle="success",
            width=24
        ).pack(pady=4)

        ttk.Button(
            ctrl_inner, 
            text="Start Ransomware Attack", 
            command=lambda: self.start(mode='malicious'), 
            bootstyle="danger",
            width=24
        ).pack(pady=4)

        self.stop_button = ttk.Button(
            ctrl_inner, 
            text="Stop Generator", 
            command=self.stop, 
            bootstyle="secondary",
            width=24
        )
        self.stop_button.pack(pady=4)

        ttk.Separator(ctrl_inner).pack(fill="x", pady=10)

        self.mode_status_lbl = ttk.Label(
            ctrl_inner, 
            text="Status: IDLE", 
            font=("Helvetica", 9, "bold"),
            bootstyle="secondary",
            anchor="center"
        )
        self.mode_status_lbl.pack(fill="x")

        ttk.Label(
            ctrl_inner, 
            text="Time Decay: 10s Window\nAuto-expires benign risk", 
            font=("Helvetica", 8),
            bootstyle="secondary",
            justify="center"
        ).pack(pady=(10, 0))

        # Real-time Matplotlib chart container
        graph_box = ttk.LabelFrame(middle_row, text=" Real-Time Behavioral Risk Score & Decay Curve ")
        graph_box.pack(side="left", fill="both", expand=True)

        graph_inner = ttk.Frame(graph_box, padding=8)
        graph_inner.pack(fill="both", expand=True)

        self.graph_canvas_tk = ttk.Frame(graph_inner)
        self.graph_canvas_tk.pack(fill="both", expand=True)

        # Row 3: Live terminal event stream
        log_box = ttk.LabelFrame(parent, text=" Live SOC Endpoint Event Stream & Audit Log ")
        log_box.pack(fill="both", expand=True)

        log_inner = ttk.Frame(log_box, padding=8)
        log_inner.pack(fill="both", expand=True)

        log_toolbar = ttk.Frame(log_inner)
        log_toolbar.pack(fill="x", pady=(0, 6))

        ttk.Label(
            log_toolbar, 
            text="Console Output (Color-coded by Heuristic Severity):", 
            font=("Helvetica", 9),
            bootstyle="secondary"
        ).pack(side="left")

        ttk.Button(
            log_toolbar, 
            text="Clear Console", 
            command=self.clear_log_console, 
            bootstyle="secondary-outline",
            padding=(6, 2)
        ).pack(side="right", padx=4)

        ttk.Button(
            log_toolbar, 
            text="Export Log", 
            command=self.export_log, 
            bootstyle="info-outline",
            padding=(6, 2)
        ).pack(side="right", padx=4)

        # Scrolled terminal text view
        self.log_text = ScrolledText(log_inner, wrap="word", font=("Consolas", 9), height=10)
        self.log_text.pack(fill="both", expand=True)
        txt_widget = _get_text(self.log_text)
        txt_widget.configure(state="disabled", background="#020617")

        # Color-coded tags for risk levels
        txt_widget.tag_config('high_risk', foreground='#f87171', font=("Consolas", 9, "bold")) # Crimson
        txt_widget.tag_config('medium_risk', foreground='#fbbf24')                              # Amber
        txt_widget.tag_config('low_risk', foreground='#38bdf8')                                 # Cyan
        txt_widget.tag_config('status', foreground='#94a3b8', font=("Consolas", 9, "italic"))  # Muted Gray

    def clear_log_console(self):
        txt_widget = _get_text(self.log_text)
        txt_widget.configure(state="normal")
        txt_widget.delete("1.0", "end")
        txt_widget.configure(state="disabled")

    def setup_graph(self):
        # Configure dark-themed styling for embedded Matplotlib canvas
        self.ax.set_title("Behavioral Risk History (Rolling Time-Decay Window)", fontsize=9, color='#94a3b8', pad=6)
        self.ax.set_xlabel("Timeline (Ticks)", fontsize=8, color='#94a3b8')
        self.ax.set_ylabel("Risk Points", fontsize=8, color='#94a3b8')

        effective = get_effective_threshold()
        self.ax.set_ylim(0, effective * 1.5)

        self.ax.axhline(effective, color=self.COLOR_RED, linestyle='--', linewidth=1.5,
                         label=f'Alert Threshold ({effective:.0f} pts)')

        self.fig.patch.set_facecolor(self.COLOR_CARD)
        self.ax.set_facecolor('#0f172a')
        self.ax.tick_params(colors='#94a3b8', labelsize=8)
        self.ax.grid(True, linestyle=':', alpha=0.25, color='#475569')

        for spine in self.ax.spines.values():
            spine.set_color('#334155')

        self.ax.legend(loc='upper right', fontsize=8, facecolor='#1e293b', edgecolor='#334155', labelcolor='#e2e8f0')

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_canvas_tk)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    def redraw_threshold_line(self):
        effective = get_effective_threshold()
        self.ax.set_ylim(0, effective * 1.5)
        for artist in list(self.ax.lines):
            if artist is not self.line:
                artist.remove()

        if THREAT_LEVEL_MULTIPLIER < 1.0:
            label = f'Threshold ({effective:.0f} - Threat Intel Sensitive)'
            color = self.COLOR_AMBER
        else:
            label = f'Threshold ({effective:.0f} pts)'
            color = self.COLOR_RED

        self.ax.axhline(effective, color=color, linestyle='--', linewidth=1.5, label=label)
        self.ax.legend(loc='upper right', fontsize=8, facecolor='#1e293b', edgecolor='#334155', labelcolor='#e2e8f0')
        self.canvas.draw_idle()

    # Configuration panel for threshold and decay window adjustments
    def build_settings_tab(self, parent):
        ttk.Label(parent, text="Detection & Heuristic Threshold Configuration", font=("Helvetica", 15, "bold")).pack(anchor="w", pady=(0, 12))

        box = ttk.LabelFrame(parent, text=" Runtime Parameters ")
        box.pack(fill="x", pady=10)

        box_inner = ttk.Frame(box, padding=16)
        box_inner.pack(fill="both", expand=True)

        t_frame = ttk.Frame(box_inner)
        t_frame.pack(fill="x", pady=8)
        ttk.Label(t_frame, text="Base Ransomware Alert Threshold:", font=("Helvetica", 10, "bold"), width=32).pack(side="left")
        self.threshold_var = tk.IntVar(value=RANSOMWARE_THRESHOLD)
        ttk.Spinbox(t_frame, from_=10, to=1000, increment=10, textvariable=self.threshold_var, width=12, bootstyle="info").pack(side="left", padx=8)
        ttk.Label(t_frame, text="(Points score required to declare a RANSOMWARE ATTACK)", font=("Helvetica", 9), bootstyle="secondary").pack(side="left")

        w_frame = ttk.Frame(box_inner)
        w_frame.pack(fill="x", pady=8)
        ttk.Label(w_frame, text="Risk Decay Window (Seconds):", font=("Helvetica", 10, "bold"), width=32).pack(side="left")
        self.window_var = tk.IntVar(value=TIME_WINDOW)
        ttk.Spinbox(w_frame, from_=1, to=120, increment=1, textvariable=self.window_var, width=12, bootstyle="info").pack(side="left", padx=8)
        ttk.Label(w_frame, text="(Duration after which a benign event score automatically decays)", font=("Helvetica", 9), bootstyle="secondary").pack(side="left")

        ttk.Button(box_inner, text="Apply Parameters", command=self.apply_settings, bootstyle="success", width=20).pack(anchor="w", pady=(16, 4))
        self.settings_status_label = ttk.Label(box_inner, text="", font=("Helvetica", 9, "bold"), bootstyle="success")
        self.settings_status_label.pack(anchor="w")

    def apply_settings(self):
        new_threshold = self.threshold_var.get()
        new_window = self.window_var.get()
        set_threshold(new_threshold)
        set_time_window(new_window)

        self.threshold_display_label.configure(text=f"{get_effective_threshold():.0f} pts")
        self.redraw_threshold_line()
        self.settings_status_label.configure(text=f"Settings updated: Base Threshold={new_threshold}, Decay Window={new_window}s")

    # Tamper-evident hash-chained audit log viewer
    def build_blockchain_tab(self, parent):
        ttk.Label(parent, text="Tamper-Evident Hash-Chained Audit Log", font=("Helvetica", 15, "bold")).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            parent, 
            text="Cryptographic SHA-256 block structure ensures past activity logs cannot be edited or deleted without failing verification.", 
            font=("Helvetica", 9), 
            bootstyle="secondary"
        ).pack(anchor="w", pady=(0, 12))

        btn_row = ttk.Frame(parent)
        btn_row.pack(fill="x", pady=(0, 10))

        ttk.Button(btn_row, text="Refresh Chain View", command=self.refresh_blockchain_view, bootstyle="info").pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Verify Integrity", command=self.verify_chain_integrity, bootstyle="success").pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Simulate Log Tampering", command=self.simulate_tampering, bootstyle="warning").pack(side="left")

        self.chain_status_label = ttk.Label(parent, text="Status: Unverified", font=("Helvetica", 11, "bold"), bootstyle="secondary")
        self.chain_status_label.pack(anchor="w", pady=(4, 8))

        self.chain_view = ScrolledText(parent, wrap="none", font=("Consolas", 9), height=18)
        self.chain_view.pack(fill="both", expand=True)
        _get_text(self.chain_view).configure(state="disabled", background="#020617")

    def refresh_blockchain_view(self):
        txt_widget = _get_text(self.chain_view)
        txt_widget.configure(state="normal")
        txt_widget.delete("1.0", "end")

        for block in self.monitor.secure_log.chain:
            ts = time.strftime("%H:%M:%S", time.localtime(block.timestamp))
            line = (f"[Block {block.index:03d}] {ts} | Payload: {block.data}\n"
                    f"     Hash: {block.hash}\n"
                    f"     Prev: {block.previous_hash}\n"
                    f"--------------------------------------------------------------------------------\n")
            txt_widget.insert("end", line)

        txt_widget.configure(state="disabled")

    def verify_chain_integrity(self):
        is_valid, broken_index = self.monitor.secure_log.verify_chain()
        if is_valid:
            self.chain_status_label.configure(text="Status: Chain Intact - No Tampering Detected", bootstyle="success")
            self.kpi_blockchain_lbl.configure(text="Hash-Chain: Intact", bootstyle="success")
            messagebox.showinfo("Log Chain Verification", "Log integrity verified successfully. All block hashes match.")
        else:
            self.chain_status_label.configure(text=f"Status: TAMPERING DETECTED at Block {broken_index}", bootstyle="danger")
            self.kpi_blockchain_lbl.configure(text=f"Chain: Tampered (B{broken_index})", bootstyle="danger")
            messagebox.showerror("Log Integrity Alert", f"Tampering detected at Block {broken_index}!\nHash mismatch indicates retroactive editing.")
        self.refresh_blockchain_view()

    def simulate_tampering(self):
        chain = self.monitor.secure_log.chain
        if len(chain) < 2:
            messagebox.showinfo("Simulate Tampering", "Run a simulation first to generate log blocks.")
            return

        target_index = random.randint(1, len(chain) - 1)
        chain[target_index].data = "*** TAMPERED LOG DATA ***"
        messagebox.showwarning("Tampering Simulated", f"Block {target_index}'s data payload was illegally modified.\nClick 'Verify Integrity' to test detection.")
        self.refresh_blockchain_view()

    # Honeypot decoy files browser and live watchdog monitoring
    def build_honeypot_tab(self, parent):
        ttk.Label(parent, text="Honeypot Deception Environment", font=("Helvetica", 15, "bold")).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            parent, 
            text="Decoy files placed in the filesystem. Legitimate users have no reason to access these files — any interaction triggers immediate alerts.",
            font=("Helvetica", 9), 
            bootstyle="secondary"
        ).pack(anchor="w", pady=(0, 12))

        if not WATCHDOG_AVAILABLE:
            ttk.Label(parent, text="Warning: 'watchdog' library not found. Run 'pip install watchdog' to enable live filesystem honeypots.", font=("Helvetica", 10, "bold"), bootstyle="warning").pack(anchor="w", pady=10)
            return

        btn_row = ttk.Frame(parent)
        btn_row.pack(fill="x", pady=(0, 12))

        self.honeypot_toggle_btn = ttk.Button(btn_row, text="Enable Honeypot Monitoring", command=self.toggle_honeypot, bootstyle="success")
        self.honeypot_toggle_btn.pack(side="left", padx=(0, 8))

        ttk.Button(btn_row, text="Open Honeypot Folder", command=self.open_honeypot_folder, bootstyle="info-outline").pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Reset Decoy Files", command=self.reset_honeypot_files, bootstyle="secondary-outline").pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Refresh List", command=self.refresh_honeypot_file_list, bootstyle="info").pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Add New Decoy File", command=self.add_custom_decoy_file, bootstyle="primary").pack(side="left")

        self.honeypot_status_label = ttk.Label(parent, text="Status: Disabled", font=("Helvetica", 11, "bold"), bootstyle="secondary")
        self.honeypot_status_label.pack(anchor="w", pady=(4, 12))

        self.honeypot_box = ttk.LabelFrame(parent, text=" Monitored Decoy Target Files (Live Directory View) ")
        self.honeypot_box.pack(fill="both", expand=True)

        self.honeypot_list_scroll = ScrollableFrame(self.honeypot_box)
        self.honeypot_list_scroll.pack(fill="both", expand=True, pady=6)

        self.refresh_honeypot_file_list()

    def refresh_honeypot_file_list(self):
        if not hasattr(self, 'honeypot_list_scroll'):
            return

        for child in self.honeypot_list_scroll.scrollable_content.winfo_children():
            child.destroy()

        if not os.path.exists(HONEYPOT_DIR):
            ensure_honeypot_files()

        try:
            files = [f for f in os.listdir(HONEYPOT_DIR) if os.path.isfile(os.path.join(HONEYPOT_DIR, f))]
        except Exception:
            files = []

        if not files:
            ttk.Label(
                self.honeypot_list_scroll.scrollable_content, 
                text="No decoy files found in honeypot folder. Click 'Reset Decoy Files' to generate defaults.", 
                font=("Helvetica", 10, "italic"),
                bootstyle="secondary"
            ).pack(anchor="w", pady=10)
            return

        for fname in sorted(files):
            fpath = os.path.join(HONEYPOT_DIR, fname)
            try:
                size_bytes = os.path.getsize(fpath)
                size_str = f"{size_bytes / 1024.0:.1f} KB" if size_bytes >= 1024 else f"{size_bytes} B"
                mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(fpath)))
            except Exception:
                size_str = "N/A"
                mtime = "N/A"

            row = ttk.Frame(self.honeypot_list_scroll.scrollable_content)
            row.pack(fill="x", expand=True, pady=3)

            lbl_file = ttk.Label(row, text=f"•  {fname}", font=("Consolas", 10, "bold"), bootstyle="light", width=34, anchor="w")
            lbl_file.pack(side="left")

            lbl_meta = ttk.Label(row, text=f"Size: {size_str}  |  Modified: {mtime}", font=("Helvetica", 9), bootstyle="secondary")
            lbl_meta.pack(side="left", padx=10)

            btn_open = ttk.Button(
                row, 
                text="Open File", 
                command=lambda p=fpath: self.open_single_file(p), 
                bootstyle="secondary-outline",
                padding=(6, 1)
            )
            btn_open.pack(side="right", padx=4)

    def open_single_file(self, filepath):
        try:
            os.startfile(filepath)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open file:\n{e}")

    def add_custom_decoy_file(self):
        if not os.path.exists(HONEYPOT_DIR):
            os.makedirs(HONEYPOT_DIR)

        filepath = filedialog.askopenfilename(
            title="Select a File to Copy into Honeypot Decoy Directory",
            filetypes=[("All Files", "*.*")]
        )
        if filepath:
            try:
                fname = os.path.basename(filepath)
                dest = os.path.join(HONEYPOT_DIR, fname)
                import shutil
                shutil.copy2(filepath, dest)
                messagebox.showinfo("Decoy Added", f"Copied '{fname}' into Honeypot Decoy Directory!")
                self.refresh_honeypot_file_list()
            except Exception as e:
                messagebox.showerror("Error", f"Could not add file: {e}")

    def toggle_honeypot(self):
        if not self.monitor.honeypot_active:
            if self.monitor.start_honeypot():
                self.honeypot_toggle_btn.configure(text="Disable Honeypot Monitoring", bootstyle="danger")
                self.honeypot_status_label.configure(text="Status: ACTIVE - Watching Decoy Folder", bootstyle="success")
                self.kpi_honeypot_lbl.configure(text="Honeypot: Active", bootstyle="success")
        else:
            self.monitor.stop_honeypot()
            self.honeypot_toggle_btn.configure(text="Enable Honeypot Monitoring", bootstyle="success")
            self.honeypot_status_label.configure(text="Status: Disabled", bootstyle="secondary")
            self.kpi_honeypot_lbl.configure(text="Honeypot: Inactive", bootstyle="secondary")

    def open_honeypot_folder(self):
        if not os.path.exists(HONEYPOT_DIR):
            os.makedirs(HONEYPOT_DIR)
        path = os.path.abspath(HONEYPOT_DIR)
        try:
            os.startfile(path)
        except AttributeError:
            messagebox.showinfo("Honeypot Directory", f"Folder path:\n{path}")

    def reset_honeypot_files(self):
        ensure_honeypot_files(force=True)
        self.refresh_honeypot_file_list()
        messagebox.showinfo("Reset Decoy Files", "All default decoy files restored with rich demo content.")

    # Live threat intelligence feed (URLhaus integration)
    def build_threat_feed_tab(self, parent):
        ttk.Label(parent, text="Live Threat Intelligence Feed (URLhaus)", font=("Helvetica", 15, "bold")).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            parent, 
            text="Fetches active ransomware indicators in the wild. Heightened ransomware activity lowers the system's effective detection threshold.",
            font=("Helvetica", 9), 
            bootstyle="secondary"
        ).pack(anchor="w", pady=(0, 12))

        if not REQUESTS_AVAILABLE:
            ttk.Label(parent, text="Warning: 'requests' library not found. Run 'pip install requests' to enable live threat feeds.", font=("Helvetica", 10, "bold"), bootstyle="warning").pack(anchor="w", pady=10)
            return

        btn_row = ttk.Frame(parent)
        btn_row.pack(fill="x", pady=(0, 10))

        self.feed_refresh_btn = ttk.Button(btn_row, text="Fetch Live Threat Feed", command=self.refresh_threat_feed, bootstyle="info")
        self.feed_refresh_btn.pack(side="left")

        self.feed_status_label = ttk.Label(parent, text="Status: Not fetched", font=("Helvetica", 10, "bold"), bootstyle="secondary")
        self.feed_status_label.pack(anchor="w", pady=(4, 4))

        self.threat_level_label = ttk.Label(parent, text="Threat Sensitivity: Standard (1.0x)", font=("Helvetica", 9), bootstyle="secondary")
        self.threat_level_label.pack(anchor="w", pady=(0, 10))

        self.feed_view = ScrolledText(parent, wrap="word", font=("Consolas", 9), height=16)
        self.feed_view.pack(fill="both", expand=True)
        _get_text(self.feed_view).configure(state="disabled", background="#020617")

    def refresh_threat_feed(self):
        self.feed_status_label.configure(text="Status: Fetching URLhaus threat data...", bootstyle="warning")
        self.feed_refresh_btn.configure(state="disabled")
        self.monitor.fetch_threat_feed_async()

    def render_threat_feed(self, success, result, ransomware_count, multiplier):
        self.feed_refresh_btn.configure(state="normal")
        txt_widget = _get_text(self.feed_view)
        txt_widget.configure(state="normal")
        txt_widget.delete("1.0", "end")

        if not success:
            self.feed_status_label.configure(text=f"Status: Error - {result}", bootstyle="danger")
        else:
            now = time.strftime("%H:%M:%S")
            self.feed_status_label.configure(text=f"Status: {len(result)} indicators fetched at {now}", bootstyle="success")

            effective = get_effective_threshold()
            if multiplier < 1.0:
                self.threat_level_label.configure(
                    text=f"HIGH THREAT WAVE: {ransomware_count} ransomware indicators detected! Sensitivity adjusted to {multiplier}x (Effective threshold: {effective:.0f} pts)",
                    bootstyle="danger"
                )
                self.sensitivity_label.configure(text=f"Multiplier: {multiplier}x (High Threat Wave)", bootstyle="danger")
            else:
                self.threat_level_label.configure(
                    text=f"THREAT POSTURE NORMAL: Threshold at {effective:.0f} pts (Multiplier: 1.0x)",
                    bootstyle="success"
                )
                self.sensitivity_label.configure(text="Multiplier: 1.0x (Normal)", bootstyle="secondary")

            for entry in result:
                line = f"[{entry['date_added']}] Threat: {entry['threat']}\n    Tags: {entry['tags'] or 'N/A'}\n    URL : {entry['url']}\n\n"
                txt_widget.insert("end", line)

        txt_widget.configure(state="disabled")
        self.threshold_display_label.configure(text=f"{get_effective_threshold():.0f} pts")
        self.redraw_threshold_line()

    # Machine learning pattern detector controls & live confidence gauge
    def build_ai_tab(self, parent):
        ttk.Label(parent, text="AI-Based Adaptive Behavioral Classification", font=("Helvetica", 15, "bold")).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            parent, 
            text="Trains a Random Forest classifier to recognize attack patterns over a rolling window of operations, independent of point thresholds.",
            font=("Helvetica", 9), 
            bootstyle="secondary"
        ).pack(anchor="w", pady=(0, 12))

        if not AI_AVAILABLE:
            ttk.Label(parent, text="Warning: 'scikit-learn' library not found. Run 'pip install scikit-learn' to enable AI detection.", font=("Helvetica", 10, "bold"), bootstyle="warning").pack(anchor="w", pady=10)
            return

        btn_row = ttk.Frame(parent)
        btn_row.pack(fill="x", pady=(0, 10))

        self.ai_train_btn = ttk.Button(btn_row, text="Train / Retrain AI Model", command=self.train_ai_model, bootstyle="success")
        self.ai_train_btn.pack(side="left")

        self.ai_status_label = ttk.Label(parent, text="Status: Model Training...", font=("Helvetica", 10, "bold"), bootstyle="warning")
        self.ai_status_label.pack(anchor="w", pady=(4, 12))

        box = ttk.LabelFrame(parent, text=" Live AI Inference Gauge ")
        box.pack(fill="x", pady=10)

        box_inner = ttk.Frame(box, padding=16)
        box_inner.pack(fill="both", expand=True)

        self.ai_confidence_label = ttk.Label(box_inner, text="Ransomware Pattern Probability: 0.0%", font=("Helvetica", 14, "bold"), bootstyle="secondary")
        self.ai_confidence_label.pack(anchor="w", pady=(0, 8))

        self.ai_confidence_bar = ttk.Progressbar(box_inner, orient="horizontal", length=500, mode="determinate", bootstyle="success-striped")
        self.ai_confidence_bar.pack(anchor="w", fill="x", pady=(0, 8))

        ttk.Label(box_inner, text=f"Note: If confidence exceeds {int(AI_ALERT_CONFIDENCE * 100)}%, AI flags an attack autonomously.", font=("Helvetica", 9), bootstyle="secondary").pack(anchor="w")

    def train_ai_model(self):
        self.ai_status_label.configure(text="Status: Training Random Forest on synthetic samples...", bootstyle="warning")
        self.ai_train_btn.configure(state="disabled")
        self.monitor.train_ai_model_async()

    def render_ai_training_result(self, success, model_or_error, accuracy):
        self.ai_train_btn.configure(state="normal")
        if success:
            acc_str = f"{accuracy * 100:.1f}%"
            self.ai_status_label.configure(text=f"Status: Trained (Test Accuracy: {acc_str})", bootstyle="success")
            self.kpi_ai_status_lbl.configure(text=f"Model: Trained ({acc_str})", bootstyle="success")
        else:
            self.ai_status_label.configure(text=f"Status: Failed - {model_or_error}", bootstyle="danger")

    # Security awareness, best practices manual, dynamic quiz, and SOC dispatch center
    def build_awareness_tab(self, parent):
        self.awareness_nb = ttk.Notebook(parent)
        self.awareness_nb.pack(fill="both", expand=True)

        guide_subtab = ttk.Frame(self.awareness_nb, padding=12)
        quiz_subtab = ttk.Frame(self.awareness_nb, padding=12)
        soc_subtab = ttk.Frame(self.awareness_nb, padding=12)

        self.awareness_nb.add(guide_subtab, text="  Enterprise Defense Manual (10 Rules)  ")
        self.awareness_nb.add(quiz_subtab, text="  Dynamic Security Quiz  ")
        self.awareness_nb.add(soc_subtab, text="  SOC Incident Dispatch Center  ")

        self.build_prevention_guide_subtab(guide_subtab)
        self.build_quiz_subtab(quiz_subtab)
        self.build_soc_subtab(soc_subtab)

        def on_awareness_tab_change(event):
            try:
                selected_text = self.awareness_nb.tab(self.awareness_nb.select(), "text")
                if "Dynamic Security Quiz" in selected_text:
                    self.load_random_quiz()
            except Exception:
                pass

        self.awareness_nb.bind("<<NotebookTabChanged>>", on_awareness_tab_change)

    def build_prevention_guide_subtab(self, parent):
        ttk.Label(parent, text="Enterprise Ransomware Defense & Incident Field Manual", font=("Helvetica", 15, "bold")).pack(anchor="w", pady=(0, 4))
        ttk.Label(parent, text="Complete 10-layer defensive blueprint for endpoint security and SOC response teams.", font=("Helvetica", 9), bootstyle="secondary").pack(anchor="w", pady=(0, 10))

        guide_box = ScrolledText(parent, wrap="word", font=("Helvetica", 10), height=18)
        guide_box.pack(fill="both", expand=True)
        txt_widget = _get_text(guide_box)
        txt_widget.configure(state="normal", background="#0f172a", foreground="#e2e8f0", padx=16, pady=16)

        # Text styles for headers and bullet points
        txt_widget.tag_config('header', font=("Helvetica", 11, "bold"), foreground="#38bdf8")
        txt_widget.tag_config('bullet', font=("Helvetica", 10), foreground="#94a3b8")

        sections = [
            ("1. Email & Spear-Phishing Security",
             "• Enforce automated blocking of dangerous attachment extensions (.exe, .js, .vbs, .hta, .ps1, .scr).\n"
             "• Implement SPF, DKIM, DMARC alignment, and external email banners to prevent spoofing."),
            ("2. Remote Access & RDP Hardening",
             "• Disable direct Internet exposure of Remote Desktop Protocol (RDP / 3389).\n"
             "• Mandate Multi-Factor Authentication (MFA) and Network Level Authentication (NLA) on all remote gateways."),
            ("3. The 3-2-1-1-0 Modern Backup Strategy",
             "• Retain 3 data copies on 2 different media types, with 1 copy stored OFFLINE, 1 copy IMMUTABLE (WORM),\n"
             "  and 0 errors verified through automated restore tests."),
            ("4. Zero Trust & Privilege Least-Privilege (PoLP)",
             "• Strip local administrative privileges from endpoint user profiles to stop privilege escalation.\n"
             "• Restrict PowerShell and command interpreter access to privileged sysadmins via AppLocker / WDAC."),
            ("5. Endpoint Detection & LSASS Memory Protection",
             "• Deploy real-time behavioral EDR to detect anti-recovery actions like 'vssadmin delete shadows'.\n"
             "• Enable Windows Credential Guard and LSASS process protection to prevent credential dumping (Mimikatz)."),
            ("6. Volume Shadow Copy (VSS) & Anti-Tampering Protections",
             "• Restrict VSS control commands exclusively to SYSTEM account contexts.\n"
             "• Lock down security agent services against unauthorized termination or disabling by malicious processes."),
            ("7. Deception Technology & Canary Files",
             "• Place decoy honeypot files with enticing file names (e.g., passwords_2025.xlsx) on key network shares.\n"
             "• Configure real-time file monitoring (Watchdog / FIM) to immediately alert on any honeypot interaction."),
            ("8. Cryptographic SIEM & Audit Log Integrity",
             "• Stream endpoint security logs in real-time to an immutable, write-once log collector.\n"
             "• Use cryptographic hash-chaining (SHA-256) to ensure log tamper-evidence during forensic audits."),
            ("9. Emergency Triage & SOC Escalation Workflow",
             "• Upon detecting high-density rename/encryption operations, automatically isolate the device network link.\n"
             "• Dispatch structured SIEM/webhook alerts to trigger Tier-2 SOC analyst investigation instantly."),
            ("10. Post-Incident Containment & Forensic Recovery",
             "• Do NOT immediately power down infected endpoints; capture volatile RAM for forensic analysis.\n"
             "• Eradicate persistence mechanisms before restoring systems from verified immutable backup images.")
        ]

        txt_widget.delete("1.0", "end")
        for title, content in sections:
            txt_widget.insert("end", f"{title}\n", 'header')
            txt_widget.insert("end", f"{content}\n\n", 'bullet')

        txt_widget.configure(state="disabled")

    # Interactive cybersecurity knowledge quiz (Easy, Medium, Hard tiers)
    def build_quiz_subtab(self, parent):
        hdr_frame = ttk.Frame(parent)
        hdr_frame.pack(fill="x", pady=(0, 6))

        ttk.Label(hdr_frame, text="Dynamic Security Knowledge Quiz", font=("Helvetica", 15, "bold")).pack(side="left")

        # Difficulty level selector
        diff_frame = ttk.Frame(hdr_frame)
        diff_frame.pack(side="right")

        ttk.Label(diff_frame, text="Difficulty: ", font=("Helvetica", 10, "bold"), bootstyle="secondary").pack(side="left", padx=(0, 4))
        self.quiz_difficulty_var = tk.StringVar(value="Easy")

        for level in ["Easy", "Medium", "Hard"]:
            style = "info-outline" if level == "Easy" else "warning-outline" if level == "Medium" else "danger-outline"
            r = ttk.Radiobutton(
                diff_frame,
                text=f" {level} ",
                variable=self.quiz_difficulty_var,
                value=level,
                bootstyle="outline-toolbutton",
                command=self.load_random_quiz
            )
            r.pack(side="left", padx=2)

        ttk.Label(parent, text="Select answers for instant feedback. Choose Easy, Medium, or Hard difficulty levels above.", font=("Helvetica", 9), bootstyle="secondary").pack(anchor="w", pady=(0, 10))

        # Scrollable card list for dynamic question display
        self.quiz_scroll = ScrollableFrame(parent)
        self.quiz_scroll.pack(fill="both", expand=True, pady=(0, 10))

        # Question pools split across three difficulty levels

        self.quiz_questions_easy = [
            ("In this system, what is the default point score threshold required to declare a RANSOMWARE ATTACK?",
             ["150 points", "10 points", "500 points"], 0),
            ("What does the AI Pattern Detection engine monitor to evaluate threat risk?",
             ["The pattern of file operations over a rolling window", "Only the desktop wallpaper", "The computer processor clock speed"], 0),
            ("Why does the system place Honeypot Decoy Files (passwords_backup.xlsx) in the decoy directory?",
             ["Because legitimate users never touch them, making ANY access an instant threat signal", "To store extra system backups", "To slow down local network speeds"], 0),
            ("Why does the Hash-Chain Log tab use SHA-256 cryptographic chaining for activity blocks?",
             ["To make past log entries tamper-evident so unauthorized edits fail verification", "To compress log file size", "To automatically email reports"], 0),
            ("Where does the Threat Intel Feed tab fetch active ransomware indicators in the wild?",
             ["URLhaus threat intelligence feed", "Google Search engine", "Local Windows event log"], 0),
            ("What should be your FIRST action if an endpoint exhibits mass encryption behavior?",
             ["Isolate the device from the network immediately (unplug Ethernet / disable Wi-Fi)", "Turn off the computer screen", "Pay the ransom demand"], 0),
        ]

        self.quiz_questions_medium = [
            ("Why does the Risk Decay Engine gradually reduce risk points over a 10-second window?",
             ["To model how suspicion fades if anomalous high-risk operations stop occurring", "To automatically reboot the computer", "To delete past security logs"], 0),
            ("Which machine learning classifier model is trained to recognize attack sequences independent of point scores?",
             ["Random Forest Classifier", "Linear Regression", "Naïve Bayes Spam Filter"], 0),
            ("What python event-monitoring library is utilized by the Honeypot engine for live filesystem watching?",
             ["watchdog (FileSystemEventHandler)", "requests library", "scikit-learn"], 0),
            ("What happens if an attacker attempts to modify a past log payload in the Hash-Chain tab?",
             ["The block hash mismatch causes verification to detect TAMPERING at that block index", "The computer immediately shuts down", "Nothing changes"], 0),
            ("How does heightened ransomware activity in the Threat Intel Feed affect detection sensitivity?",
             ["It lowers the threat multiplier (e.g. to 0.7x), making the alert threshold tighter", "It disables all defense alerts", "It increases CPU usage"], 0),
            ("In the modern 3-2-1-1-0 backup rule, what does the extra '1' and '0' represent?",
             ["1 Immutable/WORM copy and 0 errors verified through restore tests", "1 USB copy and 0 passwords", "1 email copy and 0 costs"], 0),
        ]

        self.quiz_questions_hard = [
            ("Which specific behavioral heuristic carries the HIGHEST risk score (100 pts) for defense evasion?",
             ["Security_Disable (Disabling anti-virus/firewalls)", "Mass_File_Read (10 pts)", "File_Rename_Op (25 pts)"], 0),
            ("How are feature vectors extracted from a rolling action window for Random Forest inference?",
             ["By calculating normalized action frequency ratios and average window risk score", "By scanning file extensions for .locked", "By measuring CPU clock frequencies"], 0),
            ("Which watchdog handler method detects unauthorized ransomware file renames on decoy files?",
             ["on_moved event in HoneypotEventHandler", "on_created event", "on_accessed event"], 0),
            ("How is each block's cryptographic hash computed in the SHA-256 log chain?",
             ["hashlib.sha256(index + timestamp + data + previous_hash)", "hashlib.md5(data)", "hashlib.sha1(timestamp)"], 0),
            ("What threat multiplier is applied when 5 or more recent feed entries are tagged with ransomware?",
             ["Multiplier = 0.70x (Heightened Sensitivity)", "Multiplier = 1.50x (Lower Sensitivity)", "Multiplier = 0.00x (Disabled)"], 0),
            ("Why is Volume Shadow Copy deletion via 'vssadmin delete shadows' critical to detect and block?",
             ["It destroys Windows Volume Shadow Copies to prevent system restore recovery", "It renames text files", "It speeds up Windows startup"], 0),
            ("What security control prevents credential dumping of LSASS process memory via Mimikatz?",
             ["LSASS Process Protection and Windows Credential Guard", "Disabling Windows Update", "Changing desktop wallpaper"], 0),
        ]

        self.load_random_quiz()

        btn_row = ttk.Frame(parent)
        btn_row.pack(fill="x", pady=(4, 0))
        self.quiz_result_badge = ttk.Label(btn_row, text="Select an answer for each question", font=("Helvetica", 11, "bold"), bootstyle="secondary")
        self.quiz_result_badge.pack(side="left", padx=4)

    def load_random_quiz(self):
        # Clear previous questions from scrollable content frame
        for child in self.quiz_scroll.scrollable_content.winfo_children():
            child.destroy()

        level = self.quiz_difficulty_var.get() if hasattr(self, 'quiz_difficulty_var') else "Easy"

        if level == "Hard":
            pool = self.quiz_questions_hard
        elif level == "Medium":
            pool = self.quiz_questions_medium
        else:
            pool = self.quiz_questions_easy

        sample_size = min(5, len(pool))
        self.active_quiz_selected = random.sample(pool, sample_size)
        self.quiz_data = []

        for idx, (q_text, opts, correct_idx) in enumerate(self.active_quiz_selected, 1):
            # Render question card container
            card = ttk.LabelFrame(self.quiz_scroll.scrollable_content, text=f" Question {idx} of {sample_size} [{level} Tier] ")
            card.pack(fill="x", expand=True, pady=6)

            card_inner = ttk.Frame(card, padding=12)
            card_inner.pack(fill="both", expand=True)

            lbl_title = ttk.Label(card_inner, text=q_text, font=("Helvetica", 10, "bold"), wraplength=1000, justify="left")
            lbl_title.pack(anchor="w", pady=(0, 6))

            var = tk.IntVar(value=-1)
            radios = []

            q_item = {
                'var': var,
                'correct': correct_idx,
                'radios': radios,
                'card': card,
                'title': q_text
            }

            for o_idx, opt_text in enumerate(opts):
                r = ttk.Radiobutton(
                    card_inner, 
                    text=opt_text, 
                    variable=var, 
                    value=o_idx, 
                    bootstyle="info",
                    command=lambda item=q_item: self.on_question_selected(item)
                )
                r.pack(anchor="w", padx=12, pady=3)
                radios.append((r, opt_text))

            self.quiz_data.append(q_item)

        if hasattr(self, 'quiz_result_badge'):
            self.quiz_result_badge.configure(text=f"[{level} Level] Select an answer for each question", bootstyle="secondary")

    def on_question_selected(self, q_item):
        selected = q_item['var'].get()
        correct = q_item['correct']

        if selected == -1:
            return

        for o_idx, (radio, original_text) in enumerate(q_item['radios']):
            if o_idx == correct:
                # Highlight correct option in green
                radio.configure(text=f"{original_text}  [Correct Answer]", bootstyle="success")
            elif o_idx == selected and selected != correct:
                # Mark selected wrong option in red
                radio.configure(text=f"{original_text}  [Incorrect]", bootstyle="danger")
            else:
                radio.configure(text=original_text, bootstyle="secondary")

        self.update_live_quiz_score()

    def update_live_quiz_score(self):
        answered = 0
        correct_count = 0
        total = len(self.quiz_data)
        level = self.quiz_difficulty_var.get() if hasattr(self, 'quiz_difficulty_var') else "Easy"

        for q in self.quiz_data:
            sel = q['var'].get()
            if sel != -1:
                answered += 1
                if sel == q['correct']:
                    correct_count += 1

        if answered == 0:
            badge = f"[{level} Level] Select an answer for each question"
            style = "secondary"
        elif answered < total:
            badge = f"[{level} Level] Progress: {answered}/{total} Answered  |  Current Score: {correct_count}/{answered}"
            style = "info"
        else:
            if correct_count == total:
                badge = f"Master Security Architect ({correct_count}/{total} - 100% Perfect on {level} Tier!)"
                style = "success"
            elif correct_count >= 3:
                badge = f"Senior Threat Analyst ({correct_count}/{total} - Passed {level} Tier!)"
                style = "warning"
            else:
                badge = f"Security Trainee ({correct_count}/{total} on {level} Tier - Review Prevention Manual)"
                style = "danger"

        if hasattr(self, 'quiz_result_badge'):
            self.quiz_result_badge.configure(text=badge, bootstyle=style)

    # Simulated SOC emergency alert dispatcher
    def build_soc_subtab(self, parent):
        ttk.Label(parent, text="Interactive SOC Emergency Incident Dispatch Center", font=("Helvetica", 15, "bold")).pack(anchor="w", pady=(0, 4))
        ttk.Label(parent, text="Simulate automated security event dispatching to Tier-2 SOC Incident Response teams & SIEM API endpoints.", font=("Helvetica", 9), bootstyle="secondary").pack(anchor="w", pady=(0, 12))

        grid = ttk.Frame(parent)
        grid.pack(fill="both", expand=True, pady=6)

        # Alert dispatch parameters
        left_col = ttk.LabelFrame(grid, text=" Alert Configuration ")
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 8))

        left_inner = ttk.Frame(left_col, padding=12)
        left_inner.pack(fill="both", expand=True)

        ttk.Label(left_inner, text="Severity Level:", font=("Helvetica", 9, "bold")).pack(anchor="w")
        self.soc_severity_var = tk.StringVar(value="CRITICAL (P1)")
        ttk.Combobox(left_inner, textvariable=self.soc_severity_var, values=["CRITICAL (P1)", "WARNING (P2)", "ADVISORY (P3)"], state="readonly", bootstyle="danger").pack(fill="x", pady=(2, 10))

        ttk.Label(left_inner, text="Target Channel / API Endpoint:", font=("Helvetica", 9, "bold")).pack(anchor="w")
        self.soc_channel_var = tk.StringVar(value="SOC Analyst Team Email")
        ttk.Combobox(left_inner, textvariable=self.soc_channel_var, values=["SOC Analyst Team Email", "HTTPS Webhook API (SIEM)", "PagerDuty Emergency Channel"], state="readonly", bootstyle="info").pack(fill="x", pady=(2, 10))

        ttk.Label(left_inner, text="Target Contact / URL:", font=("Helvetica", 9, "bold")).pack(anchor="w")
        self.soc_target_entry = ttk.Entry(left_inner, width=40, bootstyle="info")
        self.soc_target_entry.pack(fill="x", pady=(2, 10))
        self.soc_target_entry.insert(0, "soc-team@enterprise-security.org")

        ttk.Button(left_inner, text="Dispatch Emergency SOC Alert", command=self.dispatch_soc_alert, bootstyle="danger", width=30).pack(anchor="w", pady=(8, 0))

        # JSON payload preview pane
        right_col = ttk.LabelFrame(grid, text=" Formatted Security Payload Preview ")
        right_col.pack(side="left", fill="both", expand=True)

        right_inner = ttk.Frame(right_col, padding=8)
        right_inner.pack(fill="both", expand=True)

        self.soc_payload_view = ScrolledText(right_inner, wrap="word", font=("Consolas", 9), height=10)
        self.soc_payload_view.pack(fill="both", expand=True)

        self.update_soc_payload_preview()

    def update_soc_payload_preview(self):
        payload = {
            "event_type": "REWS_SECURITY_ALERT",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "severity": self.soc_severity_var.get(),
            "channel": self.soc_channel_var.get(),
            "target": self.soc_target_entry.get(),
            "risk_score": self.monitor.current_risk_score,
            "threshold": get_effective_threshold(),
            "ai_confidence_pct": round(self.monitor.ai_confidence * 100, 1),
            "honeypot_active": self.monitor.honeypot_active,
            "audit_block_hash": self.monitor.secure_log.chain[-1].hash
        }
        txt_widget = _get_text(self.soc_payload_view)
        txt_widget.configure(state="normal")
        txt_widget.delete("1.0", "end")
        txt_widget.insert("end", json.dumps(payload, indent=2))
        txt_widget.configure(state="disabled", background="#020617")

    def dispatch_soc_alert(self):
        self.update_soc_payload_preview()
        target = self.soc_target_entry.get().strip()
        sev = self.soc_severity_var.get()
        chan = self.soc_channel_var.get()

        if not target:
            messagebox.showwarning("Dispatch Error", "Please specify a target endpoint or email.")
            return

        now_str = time.strftime("%H:%M:%S")
        self.monitor.event_log.put((f"--- EMERGENCY {sev} SOC ALERT DISPATCHED TO {chan} ({target}) ---", "status"))
        self.monitor.secure_log.add_entry(f"SOC Dispatch: severity={sev}, channel={chan}, target={target}")

        messagebox.showinfo(
            "SOC Alert Dispatched (Simulated)", 
            f"Alert successfully generated and dispatched!\n\n"
            f"Severity  : {sev}\n"
            f"Channel   : {chan}\n"
            f"Target    : {target}\n"
            f"Timestamp : {now_str}\n"
            f"Audit Block Hash Recorded."
        )

    # Periodic GUI tick: poll queues, update graph, and refresh badges
    def start(self, mode):
        self.monitor.start_simulation(mode)

    def stop(self):
        self.monitor.stop_simulation()

    def update_gui(self):
        try:
            if not self.winfo_exists():
                return
        except Exception:
            return

        # 1. Flush event logs to terminal console
        while not self.monitor.event_log.empty():
            msg, action = self.monitor.event_log.get()
            self.log_message(msg, action)
            if "HONEYPOT ALERT" in msg:
                self.refresh_honeypot_file_list()

        # 2. Check background threat intelligence & AI trainer results
        if REQUESTS_AVAILABLE:
            while not self.monitor.threat_feed_queue.empty():
                success, result, count, mult = self.monitor.threat_feed_queue.get()
                self.render_threat_feed(success, result, count, mult)

        if AI_AVAILABLE:
            while not self.monitor.ai_status_queue.empty():
                success, model_or_error, accuracy = self.monitor.ai_status_queue.get()
                self.render_ai_training_result(success, model_or_error, accuracy)

            conf_pct = self.monitor.ai_confidence * 100
            self.kpi_ai_confidence_lbl.configure(text=f"{conf_pct:.1f}% Ransomware")
            self.ai_confidence_label.configure(text=f"Ransomware Pattern Probability: {conf_pct:.1f}%")
            self.ai_confidence_bar['value'] = conf_pct
            if conf_pct >= AI_ALERT_CONFIDENCE * 100:
                self.ai_confidence_bar.configure(bootstyle="danger-striped")
                self.kpi_ai_confidence_lbl.configure(bootstyle="danger")
            elif conf_pct >= 40:
                self.ai_confidence_bar.configure(bootstyle="warning-striped")
                self.kpi_ai_confidence_lbl.configure(bootstyle="warning")
            else:
                self.ai_confidence_bar.configure(bootstyle="success-striped")
                self.kpi_ai_confidence_lbl.configure(bootstyle="success")

        # 3. Calculate effective threshold and set UI alert banner state
        score = self.monitor.current_risk_score
        self.score_value_label.configure(text=str(int(score)))
        effective = get_effective_threshold()

        ai_alert = AI_AVAILABLE and self.monitor.ai_confidence >= AI_ALERT_CONFIDENCE

        if score >= effective or ai_alert:
            txt = "CRITICAL: RANSOMWARE ATTACK DETECTED" if score >= effective else "CRITICAL: RANSOMWARE ATTACK (AI Pattern Match)"
            self.status_badge.configure(text=txt, bootstyle="danger-inverse")
            self.line.set_color(self.COLOR_RED)
        elif score >= effective * 0.5:
            self.status_badge.configure(text="HIGH RISK WARNING", bootstyle="warning-inverse")
            self.line.set_color(self.COLOR_AMBER)
        else:
            self.status_badge.configure(text="SAFE", bootstyle="success-inverse")
            self.line.set_color(self.COLOR_CYAN)

        # Update mode status label
        if self.monitor.is_running:
            mode_txt = f"RUNNING: {self.monitor.current_mode.upper()}"
            style = "success" if self.monitor.current_mode == 'normal' else "danger"
            self.mode_status_lbl.configure(text=f"Status: {mode_txt}", bootstyle=style)
        else:
            if score > 0:
                self.mode_status_lbl.configure(text="Status: DECAYING RISK", bootstyle="warning")
            else:
                self.mode_status_lbl.configure(text="Status: IDLE", bootstyle="secondary")

        # 4. Refresh real-time Matplotlib curve and shaded area
        data = list(self.monitor.graph_data)
        if data:
            x_vals = list(range(len(data)))
            self.line.set_data(x_vals, data)

            if self.fill_poly:
                try:
                    self.fill_poly.remove()
                except Exception:
                    pass

            line_color = self.line.get_color()
            self.fill_poly = self.ax.fill_between(x_vals, data, color=line_color, alpha=0.2)

            self.ax.relim()
            self.ax.autoscale_view(scalex=True, scaley=False)

            current_max = max(data)
            target_top = max(effective * 1.5, current_max * 1.15)
            self.ax.set_ylim(0, target_top)

        try:
            if self.winfo_exists():
                self.canvas.draw_idle()
                self.after(200, self.update_gui)
        except Exception:
            pass

    def log_message(self, msg, action):
        tag = 'low_risk'
        if action in ("Security_Disable", "Delete_Backups", "Encrypting_Operation"):
            tag = 'high_risk'
        elif action in ("File_Rename_Op", "Mass_File_Read"):
            tag = 'medium_risk'
        elif action == 'status':
            tag = 'status'

        ts = time.strftime("[%H:%M:%S] ")
        txt_widget = _get_text(self.log_text)
        txt_widget.configure(state="normal")
        txt_widget.insert("end", f"{ts}{msg} - {action}\n", tag)
        txt_widget.see("end")
        txt_widget.configure(state="disabled")


if __name__ == "__main__":
    # Ensure honeypot decoy files exist before starting
    if not os.path.exists(HONEYPOT_DIR):
        ensure_honeypot_files()

    monitor = RansomwareMonitor()
    app = WarningSystemGUI(monitor)
    app.mainloop()