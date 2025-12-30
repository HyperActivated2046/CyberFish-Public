#!/usr/bin/env python3
import atexit
import base64
import csv
import hashlib
import hmac
import json
import os
import re
import queue
import random
import secrets
import smtplib
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import webbrowser
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import quote, unquote
from io import BytesIO

# Third-Party
import pyperclip
import requests
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, request, abort, redirect, render_template_string
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF

# GUI
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
try:
    import sv_ttk
    _HAS_SVTTK = True
except ImportError:
    _HAS_SVTTK = False

# Local
# (Import deferred until after sys.path update)

# -----------------------------------------------------------------------------
# PATHS / CONFIG
# -----------------------------------------------------------------------------
ROOT = Path(__file__).parent.resolve()
RESOURCES_DIR = ROOT / "resources"
sys.path.append(str(RESOURCES_DIR))

# Now we can import from the resources directory
try:
    from cloudflare_tunnel import start_tunnel, stop_tunnel
except ImportError:
    # Fallback if file is still in root during transition or dev
    try:
        from cloudflare_tunnel import start_tunnel, stop_tunnel
    except ImportError:
        print("Warning: cloudflare_tunnel module not found.")

PHISHING_DIR = RESOURCES_DIR / "PhishingTemplates"
FEEDBACK_DIR = RESOURCES_DIR / "FeedbackTemplates"
LOGS_DIR = RESOURCES_DIR / "logs"
CONFIG_PATH = RESOURCES_DIR / ".phish_config.json"
INTERACTIONS_TXT = LOGS_DIR / "interactions.log"
REPEAT_TRACKER = LOGS_DIR / "repeats.json"
STATUS_LOG = LOGS_DIR / "status.log"
CONFIG_FILE = RESOURCES_DIR / "email_config.json"
TEMP_FILES = []
_file_lock = threading.Lock()

DEFAULT_CFG = {
    "bind_host": "0.0.0.0",
    "bind_port": 8000,
    "enable_cloudflared": True,
    "cloudflared_path": "./resources/CloudFlare/cloudflared-windows-amd64.exe",
    "cloudflared_log": "./resources/CloudFlare/cld.log",
    "cloudflared_wait_seconds": 8,
    "redirect_url": "https://www.example.com",
    "immediate_feedback_enabled": False,
    "immediate_feedback_mode": "default",
    "password_pepper_hex": "",
    "log_encryption_key_hex": ""
}

SAMPLE_PHISHING_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Mock Login (Simulation)</title></head>
<body>
  <h2>Mock Login - Authorized Simulation</h2>
  <form method="post" action="/log">
    <label>Email: <input type="email" name="email" required></label><br>
    <label>Password: <input type="password" name="password"></label><br>
    <button type="submit">Continue (simulation)</button>
  </form>
</body>
</html>"""

IMMEDIATE_WARNING_HTML = """<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Security Awareness — Phishing Attempt Detected</title>
<style>
  :root {
    --bg-color: #0b1020;
    --card-bg-color: #111827;
    --tile-bg-color: #0f172a;
    --border-color: #1f2937;
    --text-color: #f1f5f9;
    --heading-color: #f87171;
    --link-color: #93c5fd;
    --badge-bg-color: #b91c1c;
    --badge-text-color: #fff;
  }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin:0; background:var(--bg-color); color:var(--text-color); transition: background .3s ease; }
  .wrap { max-width: 920px; margin: 0 auto; padding: 32px 20px 56px; }
  .card { background:var(--card-bg-color); border-radius:16px; padding:24px; box-shadow:0 10px 35px rgba(0,0,0,.35); transition: background .3s ease; }
  h1 { font-size: clamp(24px, 3vw, 34px); margin: 0 0 12px; color:var(--heading-color); transition: color .3s ease; }
  .badge { display:inline-block; background:var(--badge-bg-color); color:var(--badge-text-color); padding:6px 10px; border-radius:999px; font-weight:600; font-size:13px; letter-spacing:.3px; margin-bottom:12px; transition: background .3s ease; }
  .grid { display:grid; gap:16px; grid-template-columns: repeat(auto-fit,minmax(240px,1fr)); margin-top:14px; }
  .tile { background:var(--tile-bg-color); border:1px solid var(--border-color); border-radius:12px; padding:14px; transition: background .3s ease, border-color .3s ease; }
  .tile h3 { margin:0 0 6px; font-size:16px; color:var(--link-color); }
  ul { margin:8px 0 0 18px; padding: 0;}
  li { margin:6px 0; }
  .footer { margin-top:20px; font-size:13px; color:#cbd5e1; opacity:.9; }
  a { color:var(--link-color); }
  .info-block { background: #0c1222; border: 1px solid #1e293b; border-radius: 8px; padding: 16px; margin-top: 24px; }
  .info-block h2 { margin: 0 0 10px; font-size: 18px; color: #eab308; }
  .info-block p { margin: 4px 0; font-family: 'Courier New', Courier, monospace; font-size: 15px; }
  .info-block strong { color: #facc15; }
  #repeat-offender-warning { display: none; }
  .cta-button {
    display: inline-block;
    background-color: #3b82f6;
    color: #ffffff;
    padding: 12px 24px;
    margin: 12px 0 4px;
    border-radius: 8px;
    text-decoration: none;
    font-weight: 600;
    transition: background-color 0.2s ease-in-out, transform 0.1s ease;
    border: 1px solid #1e40af;
    box-shadow: 0 2px 5px rgba(0,0,0,0.2);
  }
  .cta-button:hover, .cta-button:focus {
    background-color: #2563eb;
    transform: translateY(-1px);
    box-shadow: 0 4px 8px rgba(0,0,0,0.25);
  }
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <span class="badge">TRAINING FEEDBACK</span>
      <div id="repeat-offender-warning">
          <h1 id="repeat-title"></h1>
          <p id="repeat-message"></p>
      </div>
      <h1>You just interacted with a simulated phishing page.</h1>
      <p>This was a safe, internal exercise to help build your security awareness. <strong>No passwords were ever stored.</strong></p>
      <p>The goal is to learn, not to punish. Review the details below to see how you can protect yourself and the organization from real-world threats.</p>

      <div class="info-block" id="user-info-display" style="display: none;">
        <h2>For Your Awareness, We See:</h2>
        <p><strong>Your IP Address:</strong> <span id="user-ip">{{USER_IP}}</span></p>
        <p><strong>Your Email:</strong> <span id="user-email">{{USER_EMAIL}}</span></p>
        <p><strong>Your Browser/System:</strong> <span id="user-agent">{{USER_AGENT}}</span></p>
        <p style="margin-top:12px; font-family: system-ui, sans-serif; font-size: 13px; color: #9ca3af;">In a real phishing attack, criminals use this information to build trust and craft more convincing attacks. Always be vigilant.</p>
      </div>

      <div class="grid">
        <div class="tile">
          <h3>How to Spot a Phish</h3>
          <ul>
            <li><strong>Check the domain:</strong> Look for misspellings, extra words, or unusual endings.</li>
            <li><strong>Urgent Language:</strong> Be wary of threats or urgent demands (“<em>verify now</em>”, “<em>account suspended</em>”).</li>
            <li><strong>Preview Links:</strong> On a computer, hover over links to see the real destination URL before you click.</li>
          </ul>
        </div>
        <div class="tile" style="text-align: center;">
          <h3>Take a Quiz, Test Your Skills!</h3>
          <p>Ready to see if you can spot a phish in the wild? Take this quiz to sharpen your skills.</p>
          <a href="https://phishingquiz.withgoogle.com/" class="cta-button" target="_blank" rel="noopener noreferrer">Take Google's Phishing Quiz</a>
          <p style="font-size:12px; color:#9ca3af; margin-top:12px;">This is an external link to a free, educational tool provided by Google.</p>
        </div>
        <div class="tile">
          <h3>What to Do Next</h3>
          <ul>
            <li><strong>Report It:</strong> In a real scenario, report suspicious messages to your IT/Security team immediately.</li>
            <li><strong>Use Unique Passwords:</strong> If you entered a real password, change it everywhere you've used it. Use a password manager to help.</li>
            <li><strong>Enable MFA:</strong> Multi-factor authentication is one of the best defenses against password theft.</li>
          </ul>
        </div>
      </div>

      <p class="footer">This was a controlled security exercise. If you have questions, please contact your security team. </p>
    </div>
  </div>

  <div id="repeat-data" data-repeat-count="{{REPEAT_COUNT}}" style="display:none;"></div>

  <script>
    document.addEventListener("DOMContentLoaded", function() {
      const repeatData = document.getElementById('repeat-data');
      const repeatCount = parseInt(repeatData.getAttribute('data-repeat-count'), 10);
      const body = document.body;

      const ip = document.getElementById('user-ip').textContent.trim();
      const email = document.getElementById('user-email').textContent.trim();
      
      // Only show the info block if we have some real data to show
      if (ip || email) {
        document.getElementById('user-info-display').style.display = 'block';
      }

      if (isNaN(repeatCount) || repeatCount <= 1) {
        // First time, do nothing special
        return;
      }

      const warningDiv = document.getElementById('repeat-offender-warning');
      const title = document.getElementById('repeat-title');
      const message = document.getElementById('repeat-message');
      warningDiv.style.display = 'block';

      if (repeatCount === 2) {
        title.textContent = "You've been here before...";
        message.textContent = "This page looks familiar, right? This is the second time you've landed on a simulated phishing page. Let's make sure it's the last.";
        
        // Make colors a bit more attention-grabbing
        body.style.setProperty('--bg-color', '#200b0b');
        body.style.setProperty('--card-bg-color', '#271111');
        body.style.setProperty('--tile-bg-color', '#2a0f0f');
        body.style.setProperty('--border-color', '#371f1f');
        body.style.setProperty('--heading-color', '#fca5a5');
        body.style.setProperty('--badge-bg-color', '#dc2626');

      } else if (repeatCount >= 3) {
        title.textContent = "ATTENTION: REPEATED RISK DETECTED";
        message.innerHTML = "This is your <strong>" + repeatCount + "rd</strong> time interacting with a phishing simulation. <strong>This is a serious security risk.</strong> You MUST improve your vigilance. DO NOT click links in suspicious emails.";

        // Use bold, high-contrast red colors
        body.style.setProperty('--bg-color', '#3f0000');
        body.style.setProperty('--card-bg-color', '#5b0000');
        body.style.setProperty('--tile-bg-color', '#4a0000');
        body.style.setProperty('--border-color', '#7f1d1d');
        body.style.setProperty('--text-color', '#fff');
        body.style.setProperty('--heading-color', '#ffcaca');
        body.style.setProperty('--badge-bg-color', '#ff0000');
        
        title.style.fontSize = '38px';
        title.style.fontWeight = 'bold';
      }
    });
  </script>

</body>
</html>"""

def check_and_regenerate_defaults():
    # 1. Ensure Directories
    for d in (PHISHING_DIR, FEEDBACK_DIR, LOGS_DIR, RESOURCES_DIR / "CloudFlare"):
        d.mkdir(parents=True, exist_ok=True)

    # 2. Config Files
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CFG, indent=2), encoding="utf-8")
    
    # 3. Sample Phishing Template
    # Only create if the directory is empty or missing sample
    if not any(PHISHING_DIR.glob("*.html")):
        (PHISHING_DIR / "sample.html").write_text(SAMPLE_PHISHING_HTML, encoding="utf-8")

    # 4. Feedback Template
    fb_path = FEEDBACK_DIR / "immediate_warning.html"
    if not fb_path.exists():
        fb_path.write_text(IMMEDIATE_WARNING_HTML, encoding="utf-8")

    # 5. Logs
    if not REPEAT_TRACKER.exists():
        initial_data = json.dumps({"emails": {}, "ips": {}}, indent=2)
        REPEAT_TRACKER.write_bytes(encrypt_data(initial_data.encode("utf-8")))

    if not INTERACTIONS_TXT.exists():
        INTERACTIONS_TXT.write_bytes(b"")

    if not STATUS_LOG.exists():
        STATUS_LOG.write_bytes(b"")


def load_email_config():
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_email_config(data: dict):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def load_cfg():
    cfg = DEFAULT_CFG.copy()
    made_changes = False
    try:
        cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
    except Exception:
        pass

    if not cfg.get("password_pepper_hex"):
        cfg["password_pepper_hex"] = secrets.token_hex(32)
        made_changes = True

    if not cfg.get("log_encryption_key_hex"):
        cfg["log_encryption_key_hex"] = secrets.token_hex(32)
        made_changes = True

    if made_changes:
        write_cfg(cfg)

    return cfg


def write_cfg(cfg):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


_pepper_cache = None


def get_pepper_bytes():
    global _pepper_cache
    if _pepper_cache:
        return _pepper_cache
    cfg = load_cfg()
    try:
        _pepper_cache = bytes.fromhex(
            cfg.get("password_pepper_hex", "")) or b"\x00"*32
    except Exception:
        _pepper_cache = b"\x00"*32
    return _pepper_cache


_log_fernet = None


def get_log_key() -> Fernet:
    global _log_fernet
    if _log_fernet:
        return _log_fernet

    cfg = load_cfg()
    key_hex = cfg.get("log_encryption_key_hex")
    key_bytes = bytes.fromhex(key_hex)
    b64_key = base64.urlsafe_b64encode(key_bytes)
    _log_fernet = Fernet(b64_key)
    return _log_fernet


def encrypt_data(data: bytes) -> bytes:
    if not data:
        return b""
    f = get_log_key()
    return f.encrypt(data)


def decrypt_data(token: bytes) -> bytes:
    if not token:
        return b""
    f = get_log_key()
    try:
        return f.decrypt(token)
    except InvalidToken:
        return b""


LOG_FILE = INTERACTIONS_TXT

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def clean_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


gui_log_callback = None


def append_log_block(block: str):
    timestamp = datetime.now(timezone.utc).strftime("[%Y-%m-%d %H:%M:%S UTC]")
    log_entry = f"{timestamp}\n{block}\n{'-' * 70}\n\n"
    encrypted_entry = encrypt_data(log_entry.encode("utf-8"))
    with _file_lock:
        with open(LOG_FILE, "ab") as f:
            f.write(encrypted_entry + b"\n")


def update_repeat_tracker(email: str, ip: str):
    data = {"emails": {}, "ips": {}}

    with _file_lock:
        if REPEAT_TRACKER.exists():
            try:
                with open(REPEAT_TRACKER, "rb") as f:
                    encrypted_content = f.read()
                decrypted_content = decrypt_data(
                    encrypted_content).decode("utf-8")
                data = json.loads(decrypted_content)
            except Exception as e:
                # If decryption fails or file is corrupt, re-initialize
                append_status_log(f"[Warning] Repeat tracker corrupted: {e}. Resetting.")
                data = {"emails": {}, "ips": {}}

        email_key = email if email and email != "[none]" else None
        ip_key = ip if ip and ip != "[none]" else None

        email_count = 0
        ip_count = 0

        if email_key:
            email_count = data["emails"].get(email_key, 0) + 1
            data["emails"][email_key] = email_count

        if ip_key:
            ip_count = data["ips"].get(ip_key, 0) + 1
            data["ips"][ip_key] = ip_count

        try:
            json_data = json.dumps(data, indent=2)
            encrypted_json = encrypt_data(json_data.encode("utf-8"))
            with open(REPEAT_TRACKER, "wb") as f:
                f.write(encrypted_json)
        except Exception:
            pass

    return email_count, ip_count


app = Flask(__name__)


def shutdown():
    func = request.environ.get('werkzeug.server.shutdown')
    if func:
        func()
    return "Server shutting down..."


class AppState:
    selected_template = None
    redirect_url = DEFAULT_CFG["redirect_url"]
    host = DEFAULT_CFG["bind_host"]
    port = DEFAULT_CFG["bind_port"]
    tunnel_proc = None
    tunnel_url = None
    immediate_feedback_enabled = DEFAULT_CFG["immediate_feedback_enabled"]
    immediate_feedback_mode = DEFAULT_CFG["immediate_feedback_mode"]
    session_start_time = None
    report_sent = False


STATE = AppState()


@app.route("/")
def index():
    if STATE.selected_template:
        safe = STATE.selected_template.replace("/", "").replace("..", "")
        p = PHISHING_DIR / f"{safe}.html"
        if not p.exists():
            abort(404)
        return p.read_text(encoding="utf-8")
    return "<h1>No template selected</h1>", 404


@app.route("/feedback")
def feedback_page():
    mode = STATE.immediate_feedback_mode or "default"
    if mode == "default":
        path = FEEDBACK_DIR / "immediate_warning.html"
    elif mode.startswith("custom:"):
        filename = mode.split("custom:", 1)[1].strip()
        safe = filename.replace("..", "").replace("/", "")
        path = FEEDBACK_DIR / safe
    else:
        path = FEEDBACK_DIR / "immediate_warning.html"
    if not path.exists():
        return "<h1>Training Feedback</h1><p>Template missing.</p>", 200

    content = path.read_text(encoding="utf-8")

    # Get data from query parameters
    ip = request.args.get("ip", "")
    email = request.args.get("email", "")
    ua = unquote(request.args.get("ua", ""))
    repeat_count = request.args.get("repeat", "0")

    # Render the template with the provided context
    return render_template_string(
        content,
        USER_IP=ip,
        USER_EMAIL=email,
        USER_AGENT=ua,
        REPEAT_COUNT=repeat_count
    )


@app.route("/log", methods=["POST"])
def log_post():
    return log_common(request.form.to_dict())


@app.route("/get", methods=["GET"])
def log_get():
    return log_common(request.args.to_dict())


def _hash_credential(value: str) -> str:
    if not value or value == "[none]":
        return ""
    pepper = get_pepper_bytes()
    return hmac.new(pepper, value.encode("utf-8"), hashlib.sha256).hexdigest()


def log_common(form):
    ip = request.headers.get(
        "CF-Connecting-IP") or request.headers.get("X-Forwarded-For") or request.remote_addr
    ua = request.headers.get("User-Agent", "")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    email = form.get("email") or form.get("Email") or "[none]"
    pwd_value = next((v for k, v in form.items()
                     if "pass" in k.lower() or "pwd" in k.lower()), "")
    _ = _hash_credential(pwd_value)  # hash & discard

    block = (
        f"--- New Submission ---\n"
        f"Time: {ts}\n"
        f"IP Address: {ip}\n"
        f"Template: {STATE.selected_template or 'N/A'}\n"
        f"Email: {email}\n"
        f"User-Agent: {ua}"
    )
    append_log_block(block)

    email_count, ip_count = update_repeat_tracker(email, ip)
    repeat_info = []
    if email_count > 1:
        repeat_info.append(f"Repeat email ({email_count}x)")
    if ip_count > 1:
        repeat_info.append(f"Repeat IP ({ip_count}x)")
    summary = " | ".join(repeat_info) if repeat_info else "First-time visitor"

    if gui_log_callback:
        gui_log_callback(
            f"Captured submission | IP: {ip} | Email: {email} | {summary}")

    if STATE.immediate_feedback_enabled:
        repeat_count = max(email_count, ip_count)
        # URL-encode the user agent to handle special characters
        safe_ua = quote(ua)
        feedback_url = f"/feedback?ip={ip}&email={email}&ua={safe_ua}&repeat={repeat_count}"
        return redirect(feedback_url)
    else:
        legit = STATE.redirect_url or DEFAULT_CFG["redirect_url"]
        return redirect(legit)


def ensure_forms_post_to_log(html_path: Path):
    try:
        soup = BeautifulSoup(html_path.read_text(
            encoding="utf-8"), "html.parser")
        for form in soup.find_all("form"):
            form["action"] = "/log"
            form["method"] = "POST"
        html_path.write_text(str(soup), encoding="utf-8")
    except Exception as e:
        print(f"Template hygiene failed for {html_path.name}: {e}")


_server_thread = None
_server_running = False


def start_flask_server():
    global _server_thread, _server_running
    if _server_running:
        return
    _server_running = True

    def _run():
        app.run(host="0.0.0.0", port=STATE.port, threaded=True)
    _server_thread = threading.Thread(target=_run, daemon=True)
    _server_thread.start()
    time.sleep(1.0)


def start_cf_tunnel(cfg, on_url):
    if not cfg.get("enable_cloudflared"):
        on_url(None, "Cloudflared disabled in config")
        return

    def _run():
        try:
            proc, url = start_tunnel(
                STATE.host,
                STATE.port,
                cloudflared_path=cfg.get(
                    "cloudflared_path", "./resources/CloudFlare/cloudflared-windows-amd64.exe"),
                logpath=cfg.get("cloudflared_log", ".cld.log"),
                wait_seconds=cfg.get("cloudflared_wait_seconds", 8),
            )
            STATE.tunnel_proc = proc
            STATE.tunnel_url = url
            on_url(url, None if url else "Failed to obtain tunnel URL (see .cld.log)")
        except Exception as e:
            on_url(None, str(e))
    threading.Thread(target=_run, daemon=True).start()


def stop_cf_tunnel():
    if STATE.tunnel_proc:
        try:
            stop_tunnel(STATE.tunnel_proc)
        except Exception:
            pass
        STATE.tunnel_proc = None
        STATE.tunnel_url = None
    global gui_log_callback
    if gui_log_callback:
        gui_log_callback("[Server] Tunnel stopped.")


def clear_all_logs():
    try:
        INTERACTIONS_TXT.write_bytes(b"")
    except Exception:
        pass
    try:
        STATUS_LOG.write_bytes(b"")
    except Exception:
        pass
    try:
        empty_data = json.dumps({"emails": {}, "ips": {}}, indent=2)
        REPEAT_TRACKER.write_bytes(encrypt_data(empty_data.encode("utf-8")))
    except Exception:
        pass


def append_status_log(text: str):
    if not text:
        return
    try:
        # Encrypt line by line or block by block
        encrypted = encrypt_data(text.encode("utf-8"))
        with _file_lock:
            with open(STATUS_LOG, "ab") as f:
                f.write(encrypted + b"\n")
    except Exception:
        pass


def read_status_log() -> str:
    try:
        if not STATUS_LOG.exists():
            return ""

        with _file_lock:
            with open(STATUS_LOG, "rb") as f:
                encrypted_lines = f.readlines()

        decrypted_lines = []
        corruption_count = 0
        for line in encrypted_lines:
            line = line.strip()
            if not line:
                continue
            res = decrypt_data(line)
            if not res and line:
                corruption_count += 1
            decrypted_lines.append(res.decode("utf-8", errors="replace"))

        if corruption_count > 0:
            decrypted_lines.append(
                f"\n[System] Warning: {corruption_count} log entries were unreadable/corrupted.\n")

        return "".join(decrypted_lines)
    except Exception:
        return "Error reading status log."


class LogRedirector:
    def __init__(self, original_stream):
        self.original_stream = original_stream
        self.buffer = ""
        self.encoding = getattr(original_stream, 'encoding', 'utf-8')

    def write(self, buf):
        if not isinstance(buf, str):
            buf = str(buf)
        try:
            if hasattr(self.original_stream, "write"):
                self.original_stream.write(buf)
                if hasattr(self.original_stream, "flush"):
                    self.original_stream.flush()
        except Exception:
            pass

        self.buffer += buf
        # Optimized split processing
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            append_status_log(line + "\n")

    def flush(self):
        try:
            if hasattr(self.original_stream, "flush"):
                self.original_stream.flush()
        except Exception:
            pass

    def isatty(self):
        if hasattr(self.original_stream, 'isatty'):
            return self.original_stream.isatty()
        return False

    def fileno(self):
        if hasattr(self.original_stream, 'fileno'):
            return self.original_stream.fileno()
        raise OSError("LogRedirector has no fileno")

    def __getattr__(self, name):
        return getattr(self.original_stream, name)


def cleanup_temp_files():
    for path in TEMP_FILES:
        try:
            p = Path(path)
            if p.exists():
                p.unlink()
        except Exception:
            pass

    # Also try to clean up the cloudflare log if configured
    try:
        cfg = load_cfg()
        cld_log = Path(cfg.get("cloudflared_log", ".cld.log"))
        if cld_log.exists():
            cld_log.unlink()
    except Exception:
        pass


atexit.register(cleanup_temp_files)


def stop_all(gui_ref=None):
    global _server_running
    if gui_ref is not None:
        try:
            if _server_running and hasattr(STATE, "report_sent") and not STATE.report_sent and STATE.session_start_time:
                ans = messagebox.askyesno(
                    "Session Report",
                    "You haven't sent a session report yet.\nDo you want to send it now before stopping?"
                )
                if ans:
                    gui_ref.send_session_report()

            title = "Stop All Services"
            message = (
                "You are about to shut down the server and tunnel.\n\n"
                "Additionally, do you want to permanently clear all logs?\n"
                "(This erases all submission history and repeat counters)\n\n"
                "• Yes: Stop services AND clear logs.\n"
                "• No: Stop services but KEEP logs.\n"
                "• Cancel: Do nothing."
            )
            resp = messagebox.askyesnocancel(
                title,
                message,
                icon=messagebox.WARNING
            )

            if resp is None:
                if gui_log_callback:
                    gui_log_callback("[App] Stop operation cancelled.")
                return
            if resp:
                clear_all_logs()
                if gui_log_callback:
                    gui_log_callback("[App] All logs have been cleared.")
        except Exception:
            pass

    stop_cf_tunnel()
    try:
        requests.post(f"http://127.0.0.1:{STATE.port}/shutdown", timeout=1.5)
    except Exception:
        pass

    _server_running = False

    cleanup_temp_files()

    if gui_log_callback:
        gui_log_callback("[Server] All services stopped.")

    if gui_ref:
        gui_ref.btn_open.config(state="disabled")
        gui_ref.btn_stop.config(state="disabled")
        gui_ref.btn_start.config(state="normal")
        STATE.tunnel_url = None


SEP = "-" * 70


def read_raw_log() -> str:
    try:
        if not INTERACTIONS_TXT.exists():
            return ""

        with _file_lock:
            with open(INTERACTIONS_TXT, "rb") as f:
                encrypted_lines = f.readlines()

        decrypted_lines = []
        corruption_detected = False
        for line in encrypted_lines:
            line = line.strip()
            if not line:
                continue
            val = decrypt_data(line)
            if not val and line:
                corruption_detected = True
            decrypted_lines.append(val.decode("utf-8"))

        if corruption_detected:
            append_status_log(
                "[Warning] Some interaction logs could not be decrypted (corruption or key mismatch).")

        return "".join(decrypted_lines)
    except Exception as e:
        append_status_log(f"[Error] Failed to read interaction log: {e}")
        return ""


def parse_log_blocks():
    raw = read_raw_log()
    if not raw.strip():
        return []
    raw = clean_ansi(raw)
    blocks = [b.strip() for b in raw.split(SEP) if b.strip()]
    parsed = []
    for block in blocks:
        lines = [l.strip() for l in block.splitlines() if l.strip()]
        try:
            data = {"time": None, "ip": None, "template": None,
                    "email": None, "user_agent": None}
            text = "\n".join(lines)
            m_time = re.search(r"Time:\s*(.+)", text)
            if m_time:
                data["time"] = m_time.group(1).strip()
            else:
                m_ts = re.search(r'^\[([^\]]+)\]', lines[0]) if lines else None
                data["time"] = m_ts.group(1).strip() if m_ts else None
            m_ip = re.search(r"IP Address:\s*(.+)", text)
            data["ip"] = m_ip.group(1).strip() if m_ip else None
            m_tpl = re.search(r"Template:\s*(.+)", text)
            data["template"] = m_tpl.group(1).strip() if m_tpl else None
            m_email = re.search(r"Email:\s*(.+)", text)
            data["email"] = m_email.group(1).strip() if m_email else None
            m_ua = re.search(r"User-Agent:\s*(.+)", text, flags=re.DOTALL)
            data["user_agent"] = m_ua.group(1).splitlines()[
                0].strip() if m_ua else None
            parsed.append(data)
        except Exception:
            parsed.append({"raw": block})
    return parsed


def export_to_csv(path: Path, entries):
    headers = ["time", "ip", "template", "email", "user_agent"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for e in entries:
            w.writerow([
                e.get("time") or "",
                e.get("ip") or "",
                e.get("template") or "",
                e.get("email") or "",
                e.get("user_agent") or "",
            ])


def export_to_txt(path: Path):
    content = read_raw_log()
    content = clean_ansi(content)
    path.write_text(content, encoding="utf-8")


def export_to_pdf(path: Path, entries):
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except Exception as e:
        raise ImportError("reportlab not installed") from e

    c = canvas.Canvas(str(path), pagesize=letter)
    width, height = letter
    margin = 40
    y = height - margin
    line_height = 12
    c.setFont("Helvetica", 10)

    c.drawString(
        margin, y, "Phishing Training - Captured Submissions")
    y -= line_height * 2

    for i, e in enumerate(entries, 1):
        lines = [
            f"{i}. Time: {e.get('time') or ''}",
            f"   IP: {e.get('ip') or ''}  Template: {e.get('template') or ''}",
            f"   Email: {e.get('email') or ''}",
            f"   User-Agent: {e.get('user_agent') or ''}",
        ]
        for ln in lines:
            if y < margin + line_height:
                c.showPage()
                y = height - margin
                c.setFont("Helvetica", 10)
            c.drawString(margin, y, ln[:1000])
            y -= line_height
        y -= line_height / 2

    c.save()


class AppGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CyberFish (Training Simulator)")
        self.geometry("1280x800")
        self.minsize(1100, 720)
        if _HAS_SVTTK:
            sv_ttk.set_theme("dark")

        self.cfg = load_cfg()
        STATE.host = self.cfg.get("bind_host", "0.0.0.0")
        STATE.port = int(self.cfg.get("bind_port", 8000))
        STATE.redirect_url = self.cfg.get(
            "redirect_url", DEFAULT_CFG["redirect_url"])
        STATE.immediate_feedback_enabled = bool(
            self.cfg.get("immediate_feedback_enabled", False))
        STATE.immediate_feedback_mode = self.cfg.get(
            "immediate_feedback_mode", "default")

        self.email_subject_var = tk.StringVar()
        self.email_body_var = tk.StringVar()
        self.target_emails_var = tk.StringVar()
        self.smtp_user_var = tk.StringVar()
        self.smtp_pass_var = tk.StringVar()
        self.summary_recipient_var = tk.StringVar()

        email_cfg = load_email_config()
        self.email_subject_var.set(email_cfg.get("subject", ""))
        self.email_body_var.set(email_cfg.get("body", ""))
        self.target_emails_var.set(email_cfg.get("targets", ""))
        self.smtp_user_var.set(email_cfg.get("smtp_user", ""))
        self.smtp_pass_var.set(email_cfg.get("smtp_pass", ""))
        self.summary_recipient_var.set(email_cfg.get("log_recipients", ""))
        self.mask_public_url_var = tk.StringVar()
        self.mask_domain_var = tk.StringVar()
        self.mask_keywords_var = tk.StringVar()
        self.mask_output_clckru_var = tk.StringVar()
        self.mask_output_osdb_var = tk.StringVar()
        self.mask_output_tinyurl_var = tk.StringVar()
        self.mask_output_isgd_var = tk.StringVar()

        self.refresh_click_count = 0
        self.easter_egg_windows = []
        self.spawn_count = 0
        self.placed_easter_egg_windows_rects = []

        self.log_queue = queue.Queue()

        self._build_widgets()
        self._load_templates()
        self._restore_feedback_template_choice_from_cfg()
        self._on_action_choice_change()  # Set initial UI state

        global gui_log_callback
        gui_log_callback = self._log_status

        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.after(100, self._process_log_queue)
        self.after(1000, self.offer_tutorial)

    def offer_tutorial(self):
        has_opened = self.cfg.get("has_opened_before", False)
        if not has_opened:
            if messagebox.askyesno("CyberFish", "Welcome!\n\nWould you like a quick interactive tour?"):
                self.start_tutorial()

            self.cfg["has_opened_before"] = True
            write_cfg(self.cfg)

    def on_closing(self):
        print("Have a good day!")
        self.destroy()

    def start_tutorial(self):
        # Define steps: (Tab Index, SubTab Index (optional), Widget Name (optional), Message)
        # Tab indices: 0=Actions, 1=Redirection, 2=Email, 3=Logs

        self.tutorial_steps = [
            {
                "tab": 2,
                "widget": "entry_smtp_user",
                "msg": "STEP 1: EMAIL SETUP\n\nEnter your SMTP Email here (e.g., Gmail address).\nThis is the account that will send the phishing emails."
            },
            {
                "tab": 2,
                "widget": "btn_save_settings",
                "msg": "STEP 1: SAVE\n\nAfter entering your password, click 'Save Settings'.\nYou can also 'Send Test Email' to verify it works."
            },
            {
                "tab": 1,
                "widget": "template_cmb",
                "msg": "STEP 2: TEMPLATE\n\nChoose a fake login page (e.g., Google, Outlook) from this list.\nOr upload your own HTML file."
            },
            {
                "tab": 1,
                "widget": "rad_feedback",
                "msg": "STEP 3: STRATEGY\n\nChoose 'Show Instant Feedback Page' for training simulations.\nIt warns users immediately after they click."
            },
            {
                "tab": 0,
                "widget": "btn_start",
                "msg": "STEP 4: LAUNCH\n\nClick 'Start Server + Tunnel' to make your site live.\nIt creates a public link accessible from anywhere."
            },
            {
                "tab": 0,
                "widget": "btn_open",
                "msg": "STEP 5: GET LINK\n\nOnce the status says 'Ready', click this to copy the public phishing link."
            },
            {
                "tab": 0,
                "widget": "btn_full_log",
                "msg": "STEP 6: STATUS\n\nMonitor the server status here or open the full log file."
            },
            {
                "tab": 1,
                "widget": "entry_public_url",
                "msg": "STEP 7: MASK LINK\n\nPaste your public link here to make it look real (e.g., drive.google.com...).\nThen click 'Generate' and 'Copy'."
            },
            {
                "tab": 2,
                "widget": "email_body_text_widget",
                "msg": "STEP 8: COMPOSE\n\nWrite your phishing email here.\nPaste the masked link into the body, then click 'Send Email'."
            },
            {
                "tab": 3,
                "widget": "logs_tree",
                "msg": "STEP 9: ANALYZE\n\nAs users take the bait, their data appears here.\nSelect an entry to see details or export the report."
            },
            {
                "tab": 0,
                "widget": "btn_quit",
                "msg": "STEP 10: CLEANUP\n\nWhen finished, click 'Stop All' to shut down and optionally wipe all logs.\n\nHappy (Ethical) Phishing!"
            }
        ]
        self.tutorial_idx = 0

        # Create the window ONCE
        if hasattr(self, "tut_win") and self.tut_win:
            self.tut_win.destroy()

        self.tut_win = tk.Toplevel(self)
        self.tut_win.title("CyberFish Tutorial")
        self.tut_win.attributes('-topmost', True)

        # Position initially but do NOT reset on every step
        x = self.winfo_rootx() + self.winfo_width() - 370
        y = self.winfo_rooty() + 50
        self.tut_win.geometry(f"350x200+{x}+{y}")
        self.tut_win.protocol("WM_DELETE_WINDOW", self.stop_tutorial)

        # Create persistent widgets inside the window
        frame = ttk.Frame(self.tut_win, padding=15)
        frame.pack(fill="both", expand=True)

        self.tut_lbl = ttk.Label(
            frame, text="", wraplength=320, font=("Segoe UI", 10))
        self.tut_lbl.pack(pady=(0, 15), fill="x", expand=True)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", side="bottom")

        ttk.Button(btn_frame, text="Quit Tutorial",
                   command=self.stop_tutorial).pack(side="left")
        self.tut_next_btn = ttk.Button(
            btn_frame, text="Next >", command=self.next_tutorial_step)
        self.tut_next_btn.pack(side="right")
        self.tut_back_btn = ttk.Button(
            btn_frame, text="< Back", command=self.prev_tutorial_step)
        self.tut_back_btn.pack(side="right", padx=5)

        self.run_tutorial_step()

    def run_tutorial_step(self):
        self.clear_highlight()
        if not hasattr(self, "tut_win") or not self.tut_win or not self.tut_win.winfo_exists():
            return

        if self.tutorial_idx >= len(self.tutorial_steps):
            self.stop_tutorial()
            return

        step = self.tutorial_steps[self.tutorial_idx]

        # Switch Tabs
        self.notebook.select(step["tab"])
        self.update_idletasks()

        # Focus Widget
        if "widget" in step and hasattr(self, step["widget"]):
            w = getattr(self, step["widget"])
            try:
                w.focus_set()
                self.highlight_widget(step["widget"])
            except:
                pass

        # Update Content without moving window
        self.tut_win.title(
            f"Tutorial {self.tutorial_idx + 1}/{len(self.tutorial_steps)}")
        self.tut_lbl.config(text=step["msg"])

        if self.tutorial_idx < len(self.tutorial_steps) - 1:
            self.tut_next_btn.config(text="Next >")
        else:
            self.tut_next_btn.config(text="Finish")

        if self.tutorial_idx > 0:
            self.tut_back_btn.state(["!disabled"])
        else:
            self.tut_back_btn.state(["disabled"])

    def clear_highlight(self):
        if hasattr(self, "tut_highlight") and self.tut_highlight:
            try:
                self.tut_highlight.destroy()
            except:
                pass
            self.tut_highlight = None

    def highlight_widget(self, widget_name):
        self.clear_highlight()
        if not hasattr(self, widget_name):
            return

        widget = getattr(self, widget_name)
        try:
            # Force update to get correct coords
            widget.update_idletasks()
            x = widget.winfo_rootx()
            y = widget.winfo_rooty()
            w = widget.winfo_width()
            h = widget.winfo_height()

            if w <= 1 or h <= 1:
                return

            self.tut_highlight = tk.Toplevel(self)
            self.tut_highlight.overrideredirect(True)
            self.tut_highlight.attributes("-topmost", True)
            self.tut_highlight.attributes("-transparentcolor", "white")
            self.tut_highlight.config(bg="red")

            # Geometry: slightly larger than widget
            pad = 3
            self.tut_highlight.geometry(
                f"{w + pad*2}x{h + pad*2}+{x - pad}+{y - pad}")

            # Inner transparent frame
            inner = tk.Frame(self.tut_highlight, bg="white")
            inner.pack(fill="both", expand=True, padx=2,
                       pady=2)  # 2px border thickness

            # Bind close
            self.tut_highlight.bind(
                "<Button-1>", lambda e: self.tut_highlight.destroy())

        except Exception as e:
            print(f"Highlight error: {e}")

    def show_tutorial_dialog(self, text):
        # Deprecated in favor of persistent window in start_tutorial
        pass

    def prev_tutorial_step(self):
        if self.tutorial_idx > 0:
            self.tutorial_idx -= 1
            self.run_tutorial_step()

    def next_tutorial_step(self):
        self.tutorial_idx += 1
        self.run_tutorial_step()

    def stop_tutorial(self):
        self.clear_highlight()
        if hasattr(self, "tut_win") and self.tut_win:
            self.tut_win.destroy()
            self.tut_win = None

    def _build_widgets(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

        # Tutorial Button (placed over the notebook's empty tab area)
        self.btn_tutorial = ttk.Button(
            self, text="Tutorial", command=self.start_tutorial)
        self.btn_tutorial.place(relx=1.0, x=-20, y=12, anchor="ne")

        actions_tab = ttk.Frame(self.notebook)
        redirect_tab = ttk.Frame(self.notebook)
        email_tab = ttk.Frame(self.notebook)
        logs_tab = ttk.Frame(self.notebook)

        self.notebook.add(actions_tab, text="Server")
        self.notebook.add(redirect_tab, text="Redirection & Templates")
        self.notebook.add(email_tab, text="Email")
        self.notebook.add(logs_tab, text="Logs")

        self._build_actions_tab(actions_tab)
        self._build_redirect_tab(redirect_tab)
        self._build_email_tab(email_tab)
        self._build_logs_tab(logs_tab)

    def on_tab_change(self, event):
        selected_tab_id = self.notebook.select()
        selected_tab_text = self.notebook.tab(selected_tab_id, "text")
        if selected_tab_text == "Logs":
            self.refresh_logs_tab()

    def _build_actions_tab(self, parent):
        pad = {"padx": 10, "pady": 8}

        # --- Actions Tab ---
        frm_mid = ttk.LabelFrame(parent, text="Controls")
        frm_mid.pack(fill="x", **pad)

        # Status Light Canvas
        self.status_canvas = tk.Canvas(
            frm_mid, width=20, height=20, highlightthickness=0)
        self.status_canvas.pack(side="left", padx=(10, 0))
        self.status_light = self.status_canvas.create_oval(
            2, 2, 18, 18, fill="red", outline="")

        self.btn_start = tk.Button(
            frm_mid, text="4. Start Server + Tunnel", command=self.on_start,
            bg="#007bff", fg="white", relief="flat")
        self.btn_start.pack(side="left", padx=6, pady=10)

        self.btn_stop = ttk.Button(
            frm_mid, text="10. Stop Tunnel", command=self.on_stop, state="disabled")
        self.btn_stop.pack(side="left", padx=6, pady=6)

        self.btn_open = ttk.Button(
            frm_mid, text="5. Copy Public URL", command=self.on_copy_url, state="disabled")
        self.btn_open.pack(side="left", padx=6, pady=6)

        self.btn_full_log = ttk.Button(
            frm_mid, text="6. Open Status Log", command=self.on_open_status_log)
        self.btn_full_log.pack(side="left", padx=6, pady=6)

        self.btn_report = ttk.Button(
            frm_mid, text="10. Send Session Report", command=self.send_session_report)
        self.btn_report.pack(side="left", padx=6, pady=6)

        self.btn_quit = ttk.Button(
            frm_mid, text="11. Stop All & Clear Logs", command=lambda: stop_all(self))
        self.btn_quit.pack(side="left", padx=6, pady=6)

        frm_status = ttk.LabelFrame(parent, text="Status")
        frm_status.pack(fill="both", expand=True, **pad)

        # Use grid for scrollbars instead of ScrolledText to allow horizontal scrolling
        # and wrap="none" to fix resize lag
        frm_inner = ttk.Frame(frm_status)
        frm_inner.pack(fill="both", expand=True, padx=6, pady=6)
        frm_inner.rowconfigure(0, weight=1)
        frm_inner.columnconfigure(0, weight=1)

        # Changed wrap to "word"
        self.txt_status = tk.Text(frm_inner, height=10, wrap="word")
        self.txt_status.grid(row=0, column=0, sticky="nsew")

        # Removed scrollbar definitions and grid calls

        self._log_status("Practice Ethical Phishing!")

    def _build_redirect_tab(self, parent):
        pad = {"padx": 10, "pady": 8}

        # --- Redirection & Templates Tab ---
        frm_template = ttk.LabelFrame(
            parent, text="Phishing Page Template")
        frm_template.pack(fill="x", **pad)

        ttk.Label(frm_template, text="Template:").grid(
            row=0, column=0, sticky="w", padx=6, pady=6)
        self.template_var = tk.StringVar()
        self.template_cmb = ttk.Combobox(
            frm_template, textvariable=self.template_var, state="readonly", width=40)
        self.template_cmb.grid(row=0, column=1, sticky="w", padx=6, pady=6)

        self.btn_upload = ttk.Button(
            frm_template, text="2. Upload Template", command=self.on_upload_template)
        self.btn_upload.grid(row=0, column=2, padx=6, pady=6)

        self.btn_preview = ttk.Button(
            frm_template, text="Preview", command=self.on_preview_template)
        self.btn_preview.grid(row=0, column=3, padx=6, pady=6)

        frm_action = ttk.LabelFrame(
            parent, text="Action After Submission")
        frm_action.pack(fill="x", **pad)
        frm_action.columnconfigure(1, weight=1)

        self.redirect_action_var = tk.StringVar(
            value="redirect" if not STATE.immediate_feedback_enabled else "feedback")

        # Radio buttons for action
        self.rad_redirect = ttk.Radiobutton(frm_action, text="Redirect to URL",
                                            variable=self.redirect_action_var, value="redirect",
                                            command=self._on_action_choice_change)
        self.rad_redirect.grid(row=0, column=0, sticky="w", padx=6, pady=4)

        self.rad_feedback = ttk.Radiobutton(frm_action, text="Show Instant Feedback Page",
                                            variable=self.redirect_action_var, value="feedback",
                                            command=self._on_action_choice_change)
        self.rad_feedback.grid(row=2, column=0, sticky="w", padx=6, pady=4)

        # --- Redirect section ---
        self.frm_redirect = ttk.Frame(frm_action)
        self.frm_redirect.grid(row=1, column=0, columnspan=3,
                               sticky="ew", padx=(30, 6), pady=4)
        self.frm_redirect.columnconfigure(1, weight=1)

        ttk.Label(self.frm_redirect, text="URL:").grid(
            row=0, column=0, sticky="w", padx=6, pady=6)
        self.redirect_var = tk.StringVar(value=STATE.redirect_url)
        self.redirect_entry = ttk.Entry(
            self.frm_redirect, textvariable=self.redirect_var, width=60)
        self.redirect_entry.grid(row=0, column=1, sticky="ew", padx=6, pady=6)

        # --- Feedback section ---
        self.frm_feedback = ttk.Frame(frm_action)
        self.frm_feedback.grid(row=3, column=0, columnspan=3,
                               sticky="ew", padx=(30, 6), pady=4)
        self.frm_feedback.columnconfigure(1, weight=1)

        ttk.Label(self.frm_feedback, text="Feedback Page:").grid(
            row=0, column=0, sticky="w")
        self.feedback_choice_var = tk.StringVar()
        self.feedback_cmb = ttk.Combobox(self.frm_feedback, textvariable=self.feedback_choice_var, state="readonly",
                                         values=["Big warning (default)", "Import your own…"], width=40)
        self.feedback_cmb.grid(row=0, column=1, sticky="ew", padx=6)
        self.feedback_cmb.bind("<<ComboboxSelected>>",
                               self._on_feedback_template_choice)

        self.btn_import_feedback = ttk.Button(
            self.frm_feedback, text="3. Import HTML…", command=self._import_feedback_html)
        self.btn_import_feedback.grid(row=0, column=2, padx=6)

        self.lbl_feedback_resolved = ttk.Label(
            self.frm_feedback, text="Resolved template: ...")
        self.lbl_feedback_resolved.grid(
            row=1, column=0, columnspan=3, sticky="w", padx=6, pady=(6, 0))

        # --- URL Masker ---
        frm_mask = ttk.LabelFrame(parent, text="URL Masker")
        frm_mask.pack(fill="x", padx=10, pady=(12, 8))
        frm_mask.columnconfigure(1, weight=1)

        ttk.Label(frm_mask, text="URL to Mask:").grid(
            row=0, column=0, sticky="w", padx=6, pady=4)
        self.entry_public_url = ttk.Entry(
            frm_mask, textvariable=self.mask_public_url_var)
        self.entry_public_url.grid(
            row=0, column=1, sticky="ew", padx=6, pady=4)
        btn_get_tunnel_url = ttk.Button(
            frm_mask, text="7. Get Tunnel URL", command=self.on_get_tunnel_url)
        btn_get_tunnel_url.grid(row=0, column=2, padx=6, pady=4)

        ttk.Label(frm_mask, text="Mask Domain:").grid(
            row=1, column=0, sticky="w", padx=6, pady=4)
        entry_mask_domain = ttk.Entry(
            frm_mask, textvariable=self.mask_domain_var)
        entry_mask_domain.grid(
            row=1, column=1, columnspan=2, sticky="ew", padx=6, pady=4)
        entry_mask_domain.insert(0, "drive.google.com")

        ttk.Label(frm_mask, text="Phishing Keywords:").grid(
            row=2, column=0, sticky="w", padx=6, pady=4)
        entry_keywords = ttk.Entry(
            frm_mask, textvariable=self.mask_keywords_var)
        entry_keywords.grid(row=2, column=1, columnspan=2,
                            sticky="ew", padx=6, pady=4)
        entry_keywords.insert(0, "login-update")

        btn_generate = ttk.Button(
            frm_mask, text="7. Generate Masked URL", command=self.on_generate_masked_url)
        btn_generate.grid(row=4, column=1, sticky="e", padx=6, pady=8)

        ttk.Label(frm_mask, text="clck.ru URL:").grid(
            row=5, column=0, sticky="w", padx=6, pady=4)
        entry_output_clckru = ttk.Entry(
            frm_mask, textvariable=self.mask_output_clckru_var, state="readonly")
        entry_output_clckru.grid(row=5, column=1, sticky="ew", padx=6, pady=4)
        btn_copy_clckru = ttk.Button(
            frm_mask, text="7. Copy", command=lambda: self.on_copy_masked_url(self.mask_output_clckru_var))
        btn_copy_clckru.grid(row=5, column=2, padx=6, pady=4)

        ttk.Label(frm_mask, text="osdb.link URL:").grid(
            row=6, column=0, sticky="w", padx=6, pady=4)
        entry_output_osdb = ttk.Entry(
            frm_mask, textvariable=self.mask_output_osdb_var, state="readonly")
        entry_output_osdb.grid(row=6, column=1, sticky="ew", padx=6, pady=4)
        btn_copy_osdb = ttk.Button(
            frm_mask, text="7. Copy", command=lambda: self.on_copy_masked_url(self.mask_output_osdb_var))
        btn_copy_osdb.grid(row=6, column=2, padx=6, pady=4)

        ttk.Label(frm_mask, text="TinyURL URL:").grid(
            row=7, column=0, sticky="w", padx=6, pady=4)
        entry_output_tinyurl = ttk.Entry(
            frm_mask, textvariable=self.mask_output_tinyurl_var, state="readonly")
        entry_output_tinyurl.grid(row=7, column=1, sticky="ew", padx=6, pady=4)
        btn_copy_tinyurl = ttk.Button(
            frm_mask, text="7. Copy", command=lambda: self.on_copy_masked_url(self.mask_output_tinyurl_var))
        btn_copy_tinyurl.grid(row=7, column=2, padx=6, pady=4)

        ttk.Label(frm_mask, text="is.gd URL:").grid(
            row=8, column=0, sticky="w", padx=6, pady=4)
        entry_output_isgd = ttk.Entry(
            frm_mask, textvariable=self.mask_output_isgd_var, state="readonly")
        entry_output_isgd.grid(row=8, column=1, sticky="ew", padx=6, pady=4)
        btn_copy_isgd = ttk.Button(
            frm_mask, text="7. Copy", command=lambda: self.on_copy_masked_url(self.mask_output_isgd_var))
        btn_copy_isgd.grid(row=8, column=2, padx=6, pady=4)

    def on_get_tunnel_url(self):
        if STATE.tunnel_url:
            self.mask_public_url_var.set(STATE.tunnel_url + "/")
        else:
            messagebox.showinfo(
                "No Tunnel URL", "Tunnel is not running or URL is not yet available.")

    def on_copy_masked_url(self, url_var):
        masked_url = url_var.get()
        if masked_url and "Generating" not in masked_url and "Error" not in masked_url:
            pyperclip.copy(masked_url)
            messagebox.showinfo(
                "Copied", "Masked URL copied to clipboard.")

    def on_generate_masked_url(self):
        url_to_mask = self.mask_public_url_var.get().strip()
        mask_domain = self.mask_domain_var.get().strip()
        keywords = self.mask_keywords_var.get().strip()

        if not url_to_mask or not mask_domain:
            messagebox.showerror(
                "Error", "URL to Mask and Mask Domain are required.")
            return

        # Clean up placeholder text if user didn't edit them
        if mask_domain == "drive.google.com":
            self.mask_domain_var.set(mask_domain)
        if keywords == "login-update":
            self.mask_keywords_var.set(keywords)

        self.mask_output_clckru_var.set("Generating...")
        self.mask_output_osdb_var.set("Generating...")
        self.mask_output_tinyurl_var.set("Generating...")
        self.mask_output_isgd_var.set("Generating...")

        sanitized_url = url_to_mask.replace(" ", "")

        # Run network requests in separate threads
        threading.Thread(target=self._generate_clckru_worker, args=(
            sanitized_url, mask_domain, keywords), daemon=True).start()
        threading.Thread(target=self._generate_osdb_worker, args=(
            sanitized_url, mask_domain, keywords), daemon=True).start()
        threading.Thread(target=self._generate_tinyurl_worker, args=(
            sanitized_url, mask_domain, keywords), daemon=True).start()
        threading.Thread(target=self._generate_isgd_worker, args=(
            sanitized_url, mask_domain, keywords), daemon=True).start()

    def _generate_clckru_worker(self, url_to_mask, mask_domain, keywords):
        api_url = "https://clck.ru/--?url={}".format(
            quote(url_to_mask, safe=':/'))
        try:
            response = requests.get(api_url, timeout=10)
            response.raise_for_status()
            shortened_url = response.text.strip()

            shortened_url_no_proto = shortened_url.replace(
                "https://", "").replace("http://", "")
            if keywords:
                user_info = f"{mask_domain}-{keywords}"
            else:
                user_info = mask_domain
            final_url = f"https://{user_info}@{shortened_url_no_proto}"
            self.mask_output_clckru_var.set(final_url)
        except requests.exceptions.RequestException:
            self.mask_output_clckru_var.set("Error generating URL")

    def _generate_osdb_worker(self, url_to_mask, mask_domain, keywords):
        api_url = "https://osdb.link/api/v1/links"
        payload = {"url": url_to_mask}
        try:
            response = requests.post(api_url, json=payload, timeout=10)
            response.raise_for_status()
            shortened_url = response.json().get("link")
            if not shortened_url:
                raise requests.exceptions.RequestException(
                    "API response did not contain a link.")

            shortened_url_no_proto = shortened_url.replace(
                "https://", "").replace("http://", "")
            if keywords:
                user_info = f"{mask_domain}-{keywords}"
            else:
                user_info = mask_domain
            final_url = f"https://{user_info}@{shortened_url_no_proto}"
            self.mask_output_osdb_var.set(final_url)
        except requests.exceptions.RequestException:
            self.mask_output_osdb_var.set("Error generating URL")

    def _generate_tinyurl_worker(self, url_to_mask, mask_domain, keywords):
        api_url = "http://tinyurl.com/api-create.php?url={}".format(
            quote(url_to_mask, safe=':/'))
        try:
            response = requests.get(api_url, timeout=10)
            response.raise_for_status()
            if "error" in response.text.lower():
                raise requests.exceptions.RequestException(response.text)
            shortened_url = response.text.strip()

            shortened_url_no_proto = shortened_url.replace(
                "https://", "").replace("http://", "")
            if keywords:
                user_info = f"{mask_domain}-{keywords}"
            else:
                user_info = mask_domain
            final_url = f"https://{user_info}@{shortened_url_no_proto}"
            self.mask_output_tinyurl_var.set(final_url)
        except requests.exceptions.RequestException:
            self.mask_output_tinyurl_var.set("Error or C-flare blocked")

    def _generate_isgd_worker(self, url_to_mask, mask_domain, keywords):
        api_url = "https://is.gd/create.php?format=simple&url={}".format(
            quote(url_to_mask, safe=':/'))
        try:
            response = requests.get(api_url, timeout=10)
            response.raise_for_status()
            if "error" in response.text.lower():
                raise requests.exceptions.RequestException(response.text)
            shortened_url = response.text.strip()

            shortened_url_no_proto = shortened_url.replace(
                "https://", "").replace("http://", "")
            if keywords:
                user_info = f"{mask_domain}-{keywords}"
            else:
                user_info = mask_domain
            final_url = f"https://{user_info}@{shortened_url_no_proto}"
            self.mask_output_isgd_var.set(final_url)
        except requests.exceptions.RequestException:
            self.mask_output_isgd_var.set("Error or C-flare blocked")

    def _build_email_tab(self, parent):
        pad = {"padx": 10, "pady": 8}

        frm_settings = ttk.LabelFrame(parent, text="SMTP Settings")
        frm_settings.pack(fill="x", **pad)
        frm_settings.columnconfigure(1, weight=1)

        ttk.Label(frm_settings, text="SMTP Email:").grid(
            row=0, column=0, sticky="w", padx=6, pady=4)
        self.entry_smtp_user = ttk.Entry(
            frm_settings, textvariable=self.smtp_user_var, width=60)
        self.entry_smtp_user.grid(row=0, column=1, sticky="ew", padx=6, pady=4)

        ttk.Label(frm_settings, text="SMTP Password:").grid(
            row=1, column=0, sticky="w", padx=6, pady=4)
        self.entry_smtp_pass = ttk.Entry(
            frm_settings, textvariable=self.smtp_pass_var, show="*", width=60)
        self.entry_smtp_pass.grid(row=1, column=1, sticky="ew", padx=6, pady=4)

        ttk.Label(frm_settings, text="Log Summary Recipient Emails:").grid(
            row=2, column=0, sticky="w", padx=6, pady=4)
        self.entry_summary_recip = ttk.Entry(
            frm_settings, textvariable=self.summary_recipient_var, width=60)
        self.entry_summary_recip.grid(
            row=2, column=1, sticky="ew", padx=6, pady=4)

        self.btn_smtp_help = ttk.Button(
            frm_settings, text="Help: SMTP Setup", command=self.on_smtp_help)
        self.btn_smtp_help.grid(row=2, column=2, padx=6)

        frm_btn_settings = ttk.Frame(frm_settings)
        frm_btn_settings.grid(row=3, column=1, sticky="e", pady=10)

        self.btn_load_profile = ttk.Button(
            frm_btn_settings, text="Load Profile", command=self.on_load_profile)
        self.btn_load_profile.pack(side="left", padx=4)

        self.btn_save_profile = ttk.Button(
            frm_btn_settings, text="Save Profile", command=self.on_save_profile)
        self.btn_save_profile.pack(side="left", padx=4)

        self.btn_save_settings = ttk.Button(frm_btn_settings, text="1. Save Settings",
                                            command=self.on_save_email_settings)
        self.btn_save_settings.pack(side="left", padx=4)
        self.btn_send_test = ttk.Button(frm_btn_settings, text="1. Send Test Email",
                                        command=self.on_send_test_email)
        self.btn_send_test.pack(side="left", padx=4)

        frm_compose = ttk.LabelFrame(parent, text="Compose & Send")
        frm_compose.pack(fill="both", expand=True, **pad)
        frm_compose.columnconfigure(1, weight=1)

        ttk.Label(frm_compose, text="Email Subject:").grid(
            row=0, column=0, sticky="w", padx=6, pady=4)
        self.entry_subject = ttk.Entry(
            frm_compose, textvariable=self.email_subject_var, width=80)
        self.entry_subject.grid(row=0, column=1, sticky="ew", pady=4)

        ttk.Label(frm_compose, text="Email Body:").grid(
            row=1, column=0, sticky="nw", padx=6, pady=4)

        # Container for Email Body Text + Scrollbars
        frm_body = ttk.Frame(frm_compose)
        frm_body.grid(row=1, column=1, sticky="nsew", pady=4, padx=6)
        frm_body.rowconfigure(0, weight=1)
        frm_body.columnconfigure(0, weight=1)

        self.email_body_text_widget = tk.Text(
            frm_body, height=8, wrap="none")
        self.email_body_text_widget.insert("1.0", self.email_body_var.get())
        self.email_body_text_widget.grid(row=0, column=0, sticky="nsew")

        ysb_body = ttk.Scrollbar(
            frm_body, orient="vertical", command=self.email_body_text_widget.yview)
        ysb_body.grid(row=0, column=1, sticky="ns")
        self.email_body_text_widget["yscrollcommand"] = ysb_body.set

        xsb_body = ttk.Scrollbar(
            frm_body, orient="horizontal", command=self.email_body_text_widget.xview)
        xsb_body.grid(row=1, column=0, sticky="ew")
        self.email_body_text_widget["xscrollcommand"] = xsb_body.set

        frm_compose.rowconfigure(1, weight=1)

        # HTML Checkbox
        self.email_html_var = tk.BooleanVar(value=False)
        self.chk_html = ttk.Checkbutton(
            frm_compose, text="Send as HTML", variable=self.email_html_var)
        self.chk_html.grid(row=2, column=1, sticky="w", padx=6, pady=2)

        ttk.Label(
            frm_compose, text="Target/Recipient Emails (one per line):").grid(row=3, column=0, sticky="nw", padx=6, pady=4)

        # Container for Targets Text + Scrollbars
        frm_targets = ttk.Frame(frm_compose)
        frm_targets.grid(row=3, column=1, sticky="ew", pady=4, padx=6)
        frm_targets.rowconfigure(0, weight=1)
        frm_targets.columnconfigure(0, weight=1)

        self.target_emails_text_widget = tk.Text(
            frm_targets, height=5, wrap="none")
        self.target_emails_text_widget.insert(
            "1.0", self.target_emails_var.get().replace(",", "\n"))
        self.target_emails_text_widget.grid(row=0, column=0, sticky="nsew")

        ysb_targets = ttk.Scrollbar(
            frm_targets, orient="vertical", command=self.target_emails_text_widget.yview)
        ysb_targets.grid(row=0, column=1, sticky="ns")
        self.target_emails_text_widget["yscrollcommand"] = ysb_targets.set

        xsb_targets = ttk.Scrollbar(
            frm_targets, orient="horizontal", command=self.target_emails_text_widget.xview)
        xsb_targets.grid(row=1, column=0, sticky="ew")
        self.target_emails_text_widget["xscrollcommand"] = xsb_targets.set

        self.btn_import_emails = ttk.Button(frm_compose, text="8. Import Emails",
                                            command=lambda: self.on_import_emails(self.target_emails_text_widget))
        self.btn_import_emails.grid(
            row=4, column=1, sticky="w", pady=4, padx=6)

        frm_btn_compose = ttk.Frame(frm_compose)
        frm_btn_compose.grid(row=5, column=1, sticky="e", pady=10)
        self.btn_save_draft = ttk.Button(frm_btn_compose, text="8. Save Draft",
                                         command=lambda: self.on_save_email_settings(self.target_emails_text_widget))
        self.btn_save_draft.pack(side="left", padx=4)
        self.btn_send_email = ttk.Button(frm_btn_compose, text="8. Send Email",
                                         command=lambda: self.on_send_training_email(self.target_emails_text_widget))
        self.btn_send_email.pack(side="left", padx=4)

    def _build_logs_tab(self, parent):
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

        paned_window = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        paned_window.grid(row=0, column=0, sticky="nsew", padx=10, pady=8)

        left = ttk.Frame(paned_window)
        paned_window.add(left, weight=2)
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)

        ttk.Label(left, text="Submissions").grid(
            row=0, column=0, sticky="nw", pady=(0, 4))

        self.logs_tree = ttk.Treeview(left, columns=(
            "Time", "IP", "Email"), show="headings")
        self.logs_tree.heading("Time", text="Time")
        self.logs_tree.heading("IP", text="IP Address")
        self.logs_tree.heading("Email", text="Email")
        self.logs_tree.column("Time", width=160, anchor="w")
        self.logs_tree.column("IP", width=120, anchor="w")
        self.logs_tree.column("Email", width=200, anchor="w")

        self.logs_tree.grid(row=1, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(
            left, orient=tk.VERTICAL, command=self.logs_tree.yview)
        self.logs_tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=1, column=1, sticky="ns")

        right = ttk.Frame(paned_window)
        paned_window.add(right, weight=3)
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        ttk.Label(right, text="Details").grid(
            row=0, column=0, sticky="nw", pady=(0, 4))

        self.logs_detail_tree = ttk.Treeview(
            right, columns=("Property", "Value"), show="headings")
        self.logs_detail_tree.heading("Property", text="Property")
        self.logs_detail_tree.heading("Value", text="Value")
        self.logs_detail_tree.column(
            "Property", width=120, stretch=tk.NO, anchor="w")
        self.logs_detail_tree.column("Value", anchor="w")
        self.logs_detail_tree.grid(row=1, column=0, sticky="nsew")

        self.logs_tree.bind("<<TreeviewSelect>>", self._show_log_details)

        btn_frame = ttk.Frame(parent)
        btn_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(6, 0))

        self.btn_refresh_logs = ttk.Button(btn_frame, text="9. Refresh Logs",
                                           command=self.refresh_logs_tab)
        self.btn_refresh_logs.pack(side="left", padx=6)

        self.btn_export_csv = ttk.Button(btn_frame, text="9. Export CSV",
                                         command=self.do_export_csv)
        self.btn_export_csv.pack(side="left", padx=6)

        self.btn_export_txt = ttk.Button(btn_frame, text="9. Export TXT (clean)",
                                         command=self.do_export_txt)
        self.btn_export_txt.pack(side="left", padx=6)

        self.btn_export_pdf = ttk.Button(btn_frame, text="9. Export PDF",
                                         command=self.do_export_pdf)
        self.btn_export_pdf.pack(side="left", padx=6)

        ttk.Button(btn_frame, text="9. Clear ALL Logs",
                   command=self._clear_all_logs_confirm).pack(side="right", padx=6)

        self.refresh_logs_tab()

    def refresh_logs_tab(self):
        self.refresh_click_count += 1
        if self.refresh_click_count >= 10:
            self.show_easter_egg()
            self.refresh_click_count = 0  # Reset for next time

        self.log_entries = parse_log_blocks()

        has_logs = bool(self.log_entries)
        state = "normal" if has_logs else "disabled"
        if hasattr(self, 'btn_export_csv'):
            self.btn_export_csv.config(state=state)
            self.btn_export_txt.config(state=state)
            self.btn_export_pdf.config(state=state)

        for i in self.logs_tree.get_children():
            self.logs_tree.delete(i)

        for i, e in enumerate(self.log_entries):
            time_str = e.get("time", "").replace(" UTC", "")
            ip = e.get("ip") or ""
            email = e.get("email") or ""
            self.logs_tree.insert("", "end", iid=str(
                i), values=(time_str, ip, email))

        self._show_log_details()

    def show_easter_egg(self):
        if hasattr(self, 'easter_egg_windows') and self.easter_egg_windows:
            return  # Prevent multiple triggers

        self._log_status(":3")
        self.easter_egg_windows = []
        self.spawn_count = 0
        # Clear placed rectangles for new spawn
        self.placed_easter_egg_windows_rects = []
        self.spawn_next_easter_egg_window()

    def spawn_next_easter_egg_window(self):
        if self.spawn_count >= 20:
            # After all windows are spawned, wait 5 seconds then destroy them
            self.after(5000, self.destroy_easter_egg)
            return

        win = tk.Toplevel(self)
        win.title(":3")
        win.attributes("-topmost", True)  # Keep them on top

        lbl = ttk.Label(win, text=":3", font=("Segoe UI", 24, "bold"))
        lbl.pack(padx=20, pady=10)

        # Let the window manager handle size for content, but we'll use a fixed size for collision
        win.update_idletasks()
        window_width = 100  # Approximate size
        window_height = 80  # Approximate size

        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        margin = 10  # Small margin from screen edges

        max_attempts = 50  # Prevent infinite loop for finding position

        found_position = False
        for _attempt in range(max_attempts):
            x = random.randint(margin, screen_width - window_width - margin)
            y = random.randint(margin, screen_height - window_height - margin)

            overlaps = False
            for existing_x, existing_y, existing_w, existing_h in self.placed_easter_egg_windows_rects:
                # Simple AABB collision detection
                if not (x + window_width < existing_x or x > existing_x + existing_w or
                        y + window_height < existing_y or y > existing_y + existing_h):
                    overlaps = True
                    break

            if not overlaps:
                # Found a non-overlapping position
                win.geometry(f"{window_width}x{window_height}+{x}+{y}")
                self.placed_easter_egg_windows_rects.append(
                    (x, y, window_width, window_height))
                found_position = True
                break

        if not found_position:  # Fallback if all attempts fail
            x = random.randint(margin, screen_width - window_width - margin)
            y = random.randint(margin, screen_height - window_height - margin)
            win.geometry(f"{window_width}x{window_height}+{x}+{y}")
            self.placed_easter_egg_windows_rects.append(
                (x, y, window_width, window_height))

        self.easter_egg_windows.append(win)
        self.spawn_count += 1

        # Schedule the next window to spawn
        self.after(100, self.spawn_next_easter_egg_window)

    def destroy_easter_egg(self):
        if hasattr(self, 'easter_egg_windows'):
            for win in self.easter_egg_windows:
                if win.winfo_exists():
                    win.destroy()
            self.easter_egg_windows = []

    def _show_log_details(self, evt=None):
        for i in self.logs_detail_tree.get_children():
            self.logs_detail_tree.delete(i)

        sel = self.logs_tree.selection()
        if not sel:
            return

        try:
            idx = int(sel[0])
            if idx >= len(self.log_entries):
                return
            e = self.log_entries[idx]

            details = [
                ("Time", e.get("time") or ""),
                ("IP Address", e.get("ip") or ""),
                ("Template", e.get("template") or ""),
                ("Email", e.get("email") or ""),
                ("User-Agent", e.get("user_agent") or "")
            ]

            for prop, val in details:
                self.logs_detail_tree.insert("", "end", values=(prop, val))
        except (ValueError, IndexError):
            # This can happen if the list is refreshed and the selection is momentarily invalid
            pass

    def do_export_csv(self):
        if not hasattr(self, 'log_entries') or not self.log_entries:
            messagebox.showinfo("No data", "No submissions to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        try:
            export_to_csv(Path(path), self.log_entries)
            messagebox.showinfo("Exported", f"CSV exported to {path}")
        except Exception as ex:
            messagebox.showerror("Error", f"Failed to export CSV: {ex}")

    def do_export_txt(self):
        if not hasattr(self, 'log_entries') or not self.log_entries:
            messagebox.showinfo("No data", "No submissions to export.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if not path:
            return
        try:
            export_to_txt(Path(path))
            messagebox.showinfo("Exported", f"TXT exported to {path}")
        except Exception as ex:
            messagebox.showerror("Error", f"Failed to export TXT: {ex}")

    def do_export_pdf(self):
        if not hasattr(self, 'log_entries') or not self.log_entries:
            messagebox.showinfo("No data", "No submissions to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if not path:
            return
        try:
            export_to_pdf(Path(path), self.log_entries)
            messagebox.showinfo("Exported", f"PDF exported to {path}")
        except ImportError:
            messagebox.showerror(
                "Missing library", "PDF export requires reportlab (pip install reportlab).")
        except Exception as ex:
            messagebox.showerror("Error", f"Failed to export PDF: {ex}")

    def _clear_all_logs_confirm(self):
        if messagebox.askyesno("Confirm", "This will permanently erase all logs and repeat counters. Continue?"):
            clear_all_logs()
            self.refresh_logs_tab()
            messagebox.showinfo("Cleared", "All logs were cleared.")

    def _on_action_choice_change(self):
        is_feedback = self.redirect_action_var.get() == "feedback"
        STATE.immediate_feedback_enabled = is_feedback
        self.cfg["immediate_feedback_enabled"] = is_feedback
        write_cfg(self.cfg)

        # Enable/disable sections
        for child in self.frm_redirect.winfo_children():
            child.configure(state="normal" if not is_feedback else "disabled")
        for child in self.frm_feedback.winfo_children():
            child.configure(state="normal" if is_feedback else "disabled")

    def _restore_feedback_template_choice_from_cfg(self):
        mode = self.cfg.get("immediate_feedback_mode", "default")
        if mode == "default":
            self.feedback_choice_var.set("Big warning (default)")
            self.lbl_feedback_resolved.config(
                text="Resolved template: immediate_warning.html")
        elif mode.startswith("custom:"):
            fname = mode.split("custom:", 1)[1]
            stem = Path(fname).stem
            self.feedback_choice_var.set(stem)
            self.lbl_feedback_resolved.config(
                text=f"Resolved template: {fname}")
        else:
            self.feedback_choice_var.set("Big warning (default)")

    def _on_feedback_template_choice(self, evt=None):
        choice = self.feedback_choice_var.get()
        if choice == "Big warning (default)":
            STATE.immediate_feedback_mode = "default"
            self.cfg["immediate_feedback_mode"] = "default"
            write_cfg(self.cfg)
            self.lbl_feedback_resolved.config(
                text="Resolved template: immediate_warning.html")
        elif choice == "Import your own…":
            self._import_feedback_html()
        else:
            # Custom existing file
            fname = choice + ".html"
            path = FEEDBACK_DIR / fname
            if not path.exists():
                messagebox.showerror("Error", f"Feedback template not found: {fname}")
                self._load_templates()
                return

            STATE.immediate_feedback_mode = f"custom:{fname}"
            self.cfg["immediate_feedback_mode"] = STATE.immediate_feedback_mode
            write_cfg(self.cfg)
            self.lbl_feedback_resolved.config(
                text=f"Resolved template: {fname}")

    def _import_feedback_html(self):
        path = filedialog.askopenfilename(
            title="Select feedback HTML template",
            filetypes=[("HTML files", "*.html;*.htm")]
        )
        if not path:
            self._restore_feedback_template_choice_from_cfg()
            return
        src = Path(path)
        safe_name = re.sub(r'[^A-Za-z0-9_\-\.]', "_", src.name)

        dest = FEEDBACK_DIR / safe_name
        try:
            dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
            ensure_forms_post_to_log(dest)

            # Reload templates to update lists
            self._load_templates()

            # Set selection
            STATE.immediate_feedback_mode = f"custom:{safe_name}"
            self.cfg["immediate_feedback_mode"] = STATE.immediate_feedback_mode
            write_cfg(self.cfg)

            self.feedback_choice_var.set(dest.stem)
            self.lbl_feedback_resolved.config(
                text=f"Resolved template: {safe_name}")

            messagebox.showinfo(
                "Imported", f"Custom feedback template saved as {safe_name}")
        except Exception as e:
            messagebox.showerror(
                "Error", f"Failed to import feedback template:\n{e}")

    def _load_templates(self):
        # Ensure directories exist (in case user deleted them)
        PHISHING_DIR.mkdir(parents=True, exist_ok=True)
        FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)

        # Load Phishing Templates
        phishing = [x.stem for x in PHISHING_DIR.glob("*.html")]
        if phishing:
            self.template_cmb["values"] = phishing
            curr = self.template_cmb.get()
            if not curr or curr not in phishing:
                self.template_cmb.current(0)
        else:
            self.template_cmb["values"] = ["(No templates found)"]
            self.template_cmb.current(0)

        # Load Feedback Templates
        feedback_stems = [x.stem for x in FEEDBACK_DIR.glob("*.html")]

        # Build Feedback Combo
        fb_values = ["Big warning (default)"]
        for f in feedback_stems:
            if f != "immediate_warning":
                fb_values.append(f)
        fb_values.append("Import your own…")
        self.feedback_cmb["values"] = fb_values
        
        # Verify current feedback selection is still valid
        curr_fb = self.feedback_choice_var.get()
        if curr_fb and curr_fb not in fb_values:
             self.feedback_choice_var.set("Big warning (default)")
             self._on_feedback_template_choice()

    def _log_status(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{ts}] {msg}"
        self.log_queue.put(formatted)

        # Print to terminal (captured by LogRedirector -> STATUS_LOG)
        print(formatted)

    def _process_log_queue(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                if hasattr(self, 'txt_status') and self.txt_status.winfo_exists():
                    self.txt_status.insert("end", msg + "\n")
                    # Limit to last 500 lines to prevent lag
                    num_lines = int(self.txt_status.index(
                        'end-1c').split('.')[0])
                    if num_lines > 500:
                        self.txt_status.delete("1.0", f"{num_lines - 500}.0")
                    self.txt_status.see("end")
        except queue.Empty:
            pass
        self.after(100, self._process_log_queue)

    def set_status_light(self, color):
        if hasattr(self, 'status_canvas'):
            self.status_canvas.itemconfig(self.status_light, fill=color)

    def on_preview_template(self):
        tmpl = self.template_var.get().strip()
        if not tmpl or tmpl == "(No templates found)":
            messagebox.showwarning("No Selection", "Please select a valid template to preview.")
            return
            
        path = PHISHING_DIR / f"{tmpl}.html"
        if path.exists():
            webbrowser.open(f"file://{path.resolve()}")
        else:
            messagebox.showerror("Missing File", f"Could not find {path}")

    def on_smtp_help(self):
        msg = (
            "To send emails via Gmail, you likely need an 'App Password' because "
            "standard passwords are blocked for security.\n\n"
            "Steps:\n"
            "1. Enable 2-Step Verification on your Google Account.\n"
            "2. Go to 'App passwords' (search for it in Google Account settings).\n"
            "3. Generate a new password (select 'Mail' and 'Windows Computer').\n"
            "4. Use that 16-character password here instead of your login password.\n\n"
            "Would you like to open the Google App Passwords support page?"
        )
        if messagebox.askyesno("SMTP Setup Help", msg):
            webbrowser.open(
                "https://support.google.com/accounts/answer/185833")

    def on_load_profile(self):
        path = filedialog.askopenfilename(
            title="Load Email Profile", filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.email_subject_var.set(data.get("subject", ""))
            self.email_body_var.set(data.get("body", ""))
            self.target_emails_var.set(data.get("targets", ""))

            # Update text widgets
            if hasattr(self, 'email_body_text_widget'):
                self.email_body_text_widget.delete("1.0", "end")
                self.email_body_text_widget.insert("1.0", data.get("body", ""))

            if hasattr(self, 'email_html_var'):
                self.email_html_var.set(data.get("is_html", False))

            if hasattr(self, 'target_emails_text_widget'):
                self.target_emails_text_widget.delete("1.0", "end")
                self.target_emails_text_widget.insert(
                    "1.0", data.get("targets", "").replace(",", "\n"))

            messagebox.showinfo("Loaded", "Profile loaded successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load profile: {e}")

    def on_save_profile(self):
        # Sync from widgets first
        if hasattr(self, 'email_body_text_widget'):
            self.email_body_var.set(
                self.email_body_text_widget.get("1.0", "end").strip())
        if hasattr(self, 'target_emails_text_widget'):
            targets = ",".join(self.target_emails_text_widget.get(
                "1.0", "end").strip().splitlines())
            self.target_emails_var.set(targets)

        path = filedialog.asksaveasfilename(
            title="Save Email Profile", defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return

        data = {
            "subject": self.email_subject_var.get(),
            "body": self.email_body_var.get(),
            "targets": self.target_emails_var.get(),
            "is_html": self.email_html_var.get() if hasattr(self, 'email_html_var') else False
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            messagebox.showinfo("Saved", f"Profile saved to {Path(path).name}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save profile: {e}")

    def on_upload_template(self):
        path = filedialog.askopenfilename(title="Select HTML Template",
                                          filetypes=[("HTML files", "*.html;*.htm")])
        if not path:
            return
        src = Path(path)

        if src.suffix.lower() not in ['.html', '.htm']:
            messagebox.showerror(
                "Invalid Format", "Only HTML files are supported.")
            return

        try:
            content = src.read_text(encoding="utf-8")
            if not content.strip():
                messagebox.showerror(
                    "Invalid Content", "The selected template file is empty.")
                return

            dest = PHISHING_DIR / src.name
            dest.write_text(content, encoding="utf-8")
            ensure_forms_post_to_log(dest)
            self._log_status(f"Uploaded template: {src.name}")
            self._load_templates()
        except Exception as e:
            messagebox.showerror(
                "Upload Error", f"Failed to upload template: {e}")
            self._log_status(f"Upload error: {e}")

    def on_start(self):
        # Refresh templates just in case folders were changed externally
        self._load_templates()
        
        tmpl = self.template_var.get().strip()
        if not tmpl or tmpl == "(No templates found)":
            messagebox.showwarning("Template required",
                                   "No valid phishing template selected.\nPlease upload or select a template.")
            return

        html_path = PHISHING_DIR / f"{tmpl}.html"
        if not html_path.exists():
            messagebox.showerror(
                "Error", f"Template file not found: {html_path.name}\nIt may have been deleted.")
            self._load_templates() # Refresh UI
            return

        STATE.selected_template = tmpl
        STATE.redirect_url = self.redirect_var.get(
        ).strip() or DEFAULT_CFG["redirect_url"]

        html_path = PHISHING_DIR / f"{tmpl}.html"
        ensure_forms_post_to_log(html_path)

        self.cfg["redirect_url"] = STATE.redirect_url
        self.cfg["immediate_feedback_enabled"] = STATE.immediate_feedback_enabled
        self.cfg["immediate_feedback_mode"] = STATE.immediate_feedback_mode
        write_cfg(self.cfg)

        self.set_status_light("yellow")
        self._log_status(
            f"Starting Flask server on http://{STATE.host}:{STATE.port} ...")
        start_flask_server()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")

        STATE.session_start_time = datetime.now(timezone.utc)
        STATE.report_sent = False

        if self.cfg.get("enable_cloudflared"):
            self._log_status("Starting Cloudflare quick tunnel ...")

            def after_tunnel(url, err):
                if err:
                    self._log_status(f"[Tunnel] ERROR: {err}")
                    self.set_status_light("red")

                    if "Failed to obtain tunnel URL" in str(err):
                        self._log_status(
                            "Issue detected. Auto-restarting server and tunnel in 3 seconds...")

                        def perform_restart():
                            stop_all(None)
                            self.on_start()
                        self.after(3000, perform_restart)
                else:
                    self._log_status(f"[Tunnel] Public URL: {url}")
                    STATE.tunnel_url = url
                    self.btn_open.config(state="normal")
                    self.set_status_light("green")
            start_cf_tunnel(self.cfg, after_tunnel)
        else:
            self._log_status("Cloudflared disabled in config.")
            self.set_status_light("green")

    def on_stop(self):
        stop_cf_tunnel()
        self._log_status("Tunnel stopped.")
        self.btn_open.config(state="disabled")
        self.btn_stop.config(state="disabled")
        self.btn_start.config(state="normal")
        self.set_status_light("red")

    def on_copy_url(self):
        if STATE.tunnel_url:
            public_url = STATE.tunnel_url + "/"
            pyperclip.copy(public_url)
            messagebox.showinfo(
                "URL Copied", "Tunnel URL has been copied to the clipboard.")
        else:
            messagebox.showinfo("No URL", "Tunnel URL not available yet.")

    def on_open_status_log(self):
        if not STATUS_LOG.exists():
            messagebox.showinfo("No Logs", "No status log file found.")
            return
        try:
            # Decrypt and read the full status log content
            content = read_status_log()
            if not content:
                messagebox.showinfo("Info", "Status log file is empty.")
                return

            # Write decrypted content to a temporary file
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log", encoding="utf-8") as tmp:
                tmp.write(content)
                tmp_path = tmp.name

            TEMP_FILES.append(tmp_path)

            # Open the temporary file with the default system viewer
            if os.name == "nt":
                os.startfile(tmp_path)
            else:
                subprocess.run(["xdg-open", tmp_path])

        except Exception as e:
            messagebox.showerror(
                "Error", f"Could not open status log file:\n{e}")

    def on_import_emails(self, txt_target_emails):
        filepath = filedialog.askopenfilename(
            title="Import Emails from File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    emails = [line.strip() for line in f if line.strip()]
                    existing = txt_target_emails.get("1.0", "end").strip()
                    combined = (existing + "\n" if existing else "") + \
                        "\n".join(emails)
                    txt_target_emails.delete("1.0", "end")
                    txt_target_emails.insert("1.0", combined)
            except Exception as e:
                messagebox.showerror(
                    "Error", f"Failed to import emails:\n{e}")

    def on_save_email_settings(self, txt_target_emails=None):
        if hasattr(self, 'email_body_text_widget') and self.email_body_text_widget.winfo_exists():
            self.email_body_var.set(
                self.email_body_text_widget.get("1.0", "end").strip())

        if txt_target_emails:
            targets = ",".join(txt_target_emails.get(
                "1.0", "end").strip().splitlines())
            self.target_emails_var.set(targets)

        # Save even if txt_target_emails is not passed (from settings tab)
        elif hasattr(self, 'target_emails_text_widget') and self.target_emails_text_widget.winfo_exists():
            targets = ",".join(self.target_emails_text_widget.get(
                "1.0", "end").strip().splitlines())
            self.target_emails_var.set(targets)

        config = {
            "subject": self.email_subject_var.get(),
            "body": self.email_body_var.get(),
            "targets": self.target_emails_var.get(),
            "smtp_user": self.smtp_user_var.get(),
            "smtp_pass": self.smtp_pass_var.get(),
            "log_recipients": self.summary_recipient_var.get()
        }
        save_email_config(config)
        messagebox.showinfo(
            "Saved", "Email settings and draft saved and will persist next time.")

    def on_send_test_email(self):
        try:
            sender = self.smtp_user_var.get().strip()
            password = self.smtp_pass_var.get().strip()
            recipients = [email.strip() for email in self.summary_recipient_var.get().split(
                ",") if email.strip()]
            subject = "CyberFish Training - SMTP Test"
            body = "This is a test email from CyberFish, confirming your SMTP setup works correctly."

            if not sender or not password or not recipients:
                messagebox.showerror(
                    "Error", "Missing SMTP credentials or recipient emails.")
                return

            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender
            msg["To"] = ", ".join(recipients)
            msg.set_content(body, subtype="plain")

            self._log_status("[Email] Sending test email...")
            self._send_smtp_message(
                "smtp.gmail.com", 587, sender, password, msg, recipients)
            self._log_status(f"[Email] Test email sent to: {', '.join(recipients)}")
            messagebox.showinfo(
                "Success", f"Test email sent to:\n{', '.join(recipients)}")
        except smtplib.SMTPAuthenticationError:
            self._log_status("[Email] Test email failed: Authentication error.")
            messagebox.showerror(
                "SMTP Authentication Failed",
                "Login rejected by the email provider.\n\n"
                "Common solutions:\n"
                "1. Use an 'App Password' instead of your main password (mandatory for Gmail/Yahoo).\n"
                "2. Check if 2-Step Verification is enabled.\n"
                "3. Verify your username (email address) is correct."
            )
        except Exception as e:
            self._log_status(f"[Email] Test email failed: {e}")
            messagebox.showerror("Error", f"Failed to send test email:\n{e}")

    def on_send_training_email(self, txt_target_emails):
        try:
            sender = self.smtp_user_var.get().strip()
            password = self.smtp_pass_var.get().strip()

            recipients = [email.strip() for email in txt_target_emails.get(
                "1.0", "end").strip().splitlines() if email.strip()]
            subject = self.email_subject_var.get().strip()
            body = self.email_body_text_widget.get("1.0", "end").strip()
            if body:
                self.email_body_var.set(body)

            if not sender or not password:
                messagebox.showerror(
                    "Error", "Missing SMTP email or password. Configure them in Email Settings.")
                return
            if not recipients:
                messagebox.showerror("Error", "No recipient emails provided.")
                return
            if not subject or not body:
                messagebox.showerror(
                    "Error", "Email subject or body is empty.")
                return

            self._log_status("[Email] Sending training email...")
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender
            msg["To"] = ", ".join(recipients)

            is_html = self.email_html_var.get()
            msg.set_content(body, subtype="html" if is_html else "plain")

            self._send_smtp_message(
                "smtp.gmail.com", 587, sender, password, msg, recipients)

            self._log_status(
                f"[Email] Training email sent to: {', '.join(recipients)}")
            messagebox.showinfo(
                "Success", f"Training email sent to:\n{', '.join(recipients)}")
        except smtplib.SMTPAuthenticationError:
            self._log_status("[Email] Training email failed: Authentication error.")
            messagebox.showerror(
                "SMTP Auth Error", "Authentication failed. For Gmail, use an App Password (2FA) or enable SMTP.")
        except Exception as e:
            self._log_status(f"[Email] Training email failed: {e}")
            self._report_email_error(e)

    def _report_email_error(self, exc):
        tb = traceback.format_exc()
        self._log_status(f"[Email] ERROR: {exc}")
        self._log_status(tb)
        messagebox.showerror(
            "Email Error", f"{exc}\n\nSee status panel for full traceback.")

    def _send_smtp_message(self, smtp_host, smtp_port, sender, password, msg, recipients):
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(sender, password)
            smtp.send_message(msg, from_addr=sender, to_addrs=recipients)

    def _generate_report_pdf(self, logs):
        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        w, h = letter

        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, h - 50, "CyberFish Session Report")

        c.setFont("Helvetica", 10)
        c.drawString(
            50, h - 70, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # IP Stats
        ip_counts = {}
        for l in logs:
            ip = l.get("ip", "Unknown")
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        # Sort by count desc
        sorted_ips = sorted(ip_counts.items(),
                            key=lambda x: x[1], reverse=True)
        top_ips = sorted_ips[:10]  # Limit to top 10 for charts
        labels = [x[0] for x in top_ips]
        data = [x[1] for x in top_ips]

        c.drawString(50, h - 90, f"Total Phished Users: {len(logs)}")
        c.drawString(250, h - 90, f"Unique IPs: {len(ip_counts)}")

        # --- Pie Chart (IP Distribution) ---
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, h - 130, "IP Distribution (Pie)")

        d_pie = Drawing(200, 200)
        pc = Pie()
        pc.x = 50
        pc.y = 50
        pc.width = 100
        pc.height = 100
        pc.data = data
        pc.labels = labels
        pc.simpleLabels = 0  # Use lines
        pc.slices.strokeWidth = 0.5
        d_pie.add(pc)
        renderPDF.draw(d_pie, c, 50, h - 350)  # x, y (bottom-left of drawing)

        # --- Bar Chart (IP Counts - Highest to Lowest) ---
        c.drawString(300, h - 130, "Top IPs (Bar)")

        d_bar = Drawing(250, 200)
        bc = VerticalBarChart()
        bc.x = 20
        bc.y = 50
        bc.height = 125
        bc.width = 200
        bc.data = [data]  # Series
        bc.strokeColor = colors.black
        bc.valueAxis.valueMin = 0
        bc.valueAxis.valueMax = max(data) + 1 if data else 10
        bc.valueAxis.valueStep = 1 if max(data) < 10 else (max(data)//5 + 1)
        bc.categoryAxis.labels.boxAnchor = 'ne'
        bc.categoryAxis.labels.dx = 8
        bc.categoryAxis.labels.dy = -2
        bc.categoryAxis.labels.angle = 30
        bc.categoryAxis.categoryNames = labels

        # Colors
        for i in range(len(data)):
            bc.bars[(0, i)].fillColor = colors.blue

        d_bar.add(bc)
        renderPDF.draw(d_bar, c, 300, h - 350)

        # --- Victim List ---
        c.setFont("Helvetica-Bold", 12)
        start_y = h - 380
        c.drawString(50, start_y, "Victim List")

        c.setFont("Helvetica", 9)
        row_y = start_y - 20
        c.drawString(50, row_y, "Time")
        c.drawString(200, row_y, "Email")
        c.drawString(350, row_y, "Template")
        c.drawString(450, row_y, "IP")

        row_y -= 15
        c.line(50, row_y + 12, 550, row_y + 12)

        for l in logs:
            if row_y < 50:
                c.showPage()
                row_y = h - 50

            c.drawString(50, row_y, str(l.get("time", "")))
            c.drawString(200, row_y, str(l.get("email", "")))
            c.drawString(350, row_y, str(l.get("template", "")))
            c.drawString(450, row_y, str(l.get("ip", "")))
            row_y -= 15

        c.save()
        buffer.seek(0)
        return buffer.read()

    def send_session_report(self):
        recipients_str = self.summary_recipient_var.get().strip()
        if not recipients_str:
            messagebox.showerror(
                "Error", "No log recipients configured. Check 'Email' tab.")
            return

        recipients = [r.strip()
                      for r in recipients_str.split(",") if r.strip()]

        # Get logs
        all_logs = parse_log_blocks()

        # Filter by session
        session_logs = []
        if STATE.session_start_time:
            start_dt = STATE.session_start_time
            # Parse log time
            for l in all_logs:
                ts_str = l.get("time", "")
                try:
                    if "UTC" in ts_str:
                        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S UTC")
                        dt = dt.replace(tzinfo=timezone.utc)
                        if dt >= start_dt:
                            session_logs.append(l)
                    else:
                        session_logs.append(l)
                except:
                    pass
        else:
            session_logs = all_logs

        if not session_logs:
            messagebox.showinfo(
                "Info", "No phishing interactions recorded in this session.")
            return

        # Generate PDF
        try:
            pdf_data = self._generate_report_pdf(session_logs)

            # Send Email
            sender = self.smtp_user_var.get().strip()
            password = self.smtp_pass_var.get().strip()

            if not sender or not password:
                messagebox.showerror("Error", "SMTP settings missing.")
                return

            msg = EmailMessage()
            msg["Subject"] = "CyberFish Session Report"
            msg["From"] = sender
            msg["To"] = ", ".join(recipients)
            msg.set_content(
                "Please find attached the phishing session report.")

            msg.add_attachment(pdf_data, maintype='application',
                               subtype='pdf', filename='session_report.pdf')

            self._send_smtp_message(
                "smtp.gmail.com", 587, sender, password, msg, recipients)

            STATE.report_sent = True
            messagebox.showinfo("Success", "Session report sent successfully.")

        except smtplib.SMTPAuthenticationError:
            self._log_status(
                "[Email] Authentication failed during report sending.")
            messagebox.showerror(
                "SMTP Auth Error", "Authentication failed. Please check your SMTP email and password settings.")
        except Exception as e:
            self._report_email_error(e)


if __name__ == "__main__":
    # Redirect stdout and stderr to capture logs
    sys.stdout = LogRedirector(sys.stdout)
    sys.stderr = LogRedirector(sys.stderr)

    check_and_regenerate_defaults()

    gui = AppGUI()
    gui.mainloop()
