"""
config.py — Central configuration for the APK Security Intelligence Platform.
Loads environment variables, defines directory paths, compiles all regex patterns,
and provides the Android permission risk classification map.
"""

import re
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Directory paths ───────────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).parent
WORKSPACE_DIR = BASE_DIR / "workspace"
REPORTS_DIR   = BASE_DIR / "reports"
SAMPLES_DIR   = BASE_DIR.parent / "samples"

WORKSPACE_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# ── External tool binary paths ────────────────────────────────────────────────
APKTOOL_PATH = "/usr/local/bin/apktool"
JADX_PATH    = "/usr/local/bin/jadx"
ADB_PATH     = "/usr/bin/adb"

# ── Secret scanner regex patterns ─────────────────────────────────────────────
# Keys are human-readable labels; values are compiled re.compile() objects.
SECRET_PATTERNS = {
    "Google API Key":         re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "AWS Access Key ID":      re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key":         re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Firebase Database URL":  re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
    "Stripe Live Secret Key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "Stripe Live Public Key": re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
    "JWT Token":              re.compile(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),
    "Private Key Block":      re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
    "Hardcoded Password":     re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]"),
    "Hardcoded Secret/Key":   re.compile(r"(?i)(?:secret|api_key|apikey|access_key)\s*[=:]\s*['\"][^'\"]{8,}['\"]"),
    "Slack Token":            re.compile(r"xox[baprs]-[0-9A-Za-z]{10,48}"),
    "GitHub Personal Token":  re.compile(r"ghp_[0-9a-zA-Z]{36}"),
}

# ── Entropy analysis settings ─────────────────────────────────────────────────
ENTROPY_THRESHOLD = 4.5
ENTROPY_KEYWORDS  = [
    "key", "token", "secret", "password",
    "api", "auth", "credential", "private",
]

# ── Android permission risk map ───────────────────────────────────────────────
# Keys are full android.permission.* strings.
# Values are dicts with "level" (DANGEROUS/HIGH/MEDIUM/NORMAL) and "reason".
PERMISSION_RISK_MAP = {
    # ── DANGEROUS ─────────────────────────────────────────────────────────────
    "android.permission.READ_SMS": {
        "level": "DANGEROUS",
        "reason": "Read all SMS messages on the device — credential codes, OTPs, private messages.",
    },
    "android.permission.RECEIVE_SMS": {
        "level": "DANGEROUS",
        "reason": "Intercept incoming SMS messages in real time, including 2FA codes.",
    },
    "android.permission.SEND_SMS": {
        "level": "DANGEROUS",
        "reason": "Send SMS messages without user interaction — potential billing fraud.",
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "level": "DANGEROUS",
        "reason": "Precise GPS location access — enables exact real-time user tracking.",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "level": "DANGEROUS",
        "reason": "Location access even when the app is not visible or in use.",
    },
    "android.permission.RECORD_AUDIO": {
        "level": "DANGEROUS",
        "reason": "Microphone access — enables silent audio recording and eavesdropping.",
    },
    "android.permission.CAMERA": {
        "level": "DANGEROUS",
        "reason": "Camera access — enables silent photo/video capture and surveillance.",
    },
    "android.permission.READ_CONTACTS": {
        "level": "DANGEROUS",
        "reason": "Read the entire device contacts list including names, emails, and phone numbers.",
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "level": "DANGEROUS",
        "reason": "Intercept and redirect outgoing phone calls.",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "level": "DANGEROUS",
        "reason": "Install arbitrary APKs at runtime — primary dropper malware vector.",
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "level": "DANGEROUS",
        "reason": "Full UI observation and interaction — enables overlay attacks and keylogging.",
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "level": "DANGEROUS",
        "reason": "Device administrator rights — can enforce policies, wipe data, lock screen.",
    },
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "level": "DANGEROUS",
        "reason": "Unrestricted read/write access to all files on external storage.",
    },

    # ── HIGH ──────────────────────────────────────────────────────────────────
    "android.permission.WRITE_CONTACTS": {
        "level": "HIGH",
        "reason": "Modify or delete any contact on the device.",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "level": "HIGH",
        "reason": "Approximate location via network — enables area-level tracking.",
    },
    "android.permission.READ_CALL_LOG": {
        "level": "HIGH",
        "reason": "Read the full call history including numbers, dates, and durations.",
    },
    "android.permission.WRITE_CALL_LOG": {
        "level": "HIGH",
        "reason": "Modify or delete call history records.",
    },
    "android.permission.READ_PHONE_STATE": {
        "level": "HIGH",
        "reason": "Access IMEI, phone number, SIM info, and active call state.",
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "level": "HIGH",
        "reason": "Read all files stored on external storage.",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "level": "HIGH",
        "reason": "Write or delete any file on external storage.",
    },
    "android.permission.BLUETOOTH_SCAN": {
        "level": "HIGH",
        "reason": "Scan for nearby Bluetooth devices — enables proximity and location tracking.",
    },
    "android.permission.DELETE_PACKAGES": {
        "level": "HIGH",
        "reason": "Silently uninstall any application from the device.",
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "level": "HIGH",
        "reason": "Draw overlays on top of other apps — primary phishing and clickjacking vector.",
    },
    "android.permission.GET_ACCOUNTS": {
        "level": "HIGH",
        "reason": "Enumerate all Google and third-party accounts configured on the device.",
    },

    # ── MEDIUM ────────────────────────────────────────────────────────────────
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "level": "MEDIUM",
        "reason": "Automatically start on device boot — persistence mechanism for background services.",
    },
    "android.permission.CHANGE_NETWORK_STATE": {
        "level": "MEDIUM",
        "reason": "Enable or disable network connectivity programmatically.",
    },
    "android.permission.BLUETOOTH": {
        "level": "MEDIUM",
        "reason": "Initiate connections to paired Bluetooth devices.",
    },
    "android.permission.USE_BIOMETRIC": {
        "level": "MEDIUM",
        "reason": "Access the system biometric authentication framework.",
    },
    "android.permission.USE_FINGERPRINT": {
        "level": "MEDIUM",
        "reason": "Access the fingerprint sensor authentication APIs (deprecated but still used).",
    },
    "android.permission.NFC": {
        "level": "MEDIUM",
        "reason": "NFC communication — potential relay and card-skimming attacks.",
    },
    "android.permission.CHANGE_WIFI_STATE": {
        "level": "MEDIUM",
        "reason": "Connect to or disconnect from Wi-Fi networks without user approval.",
    },

    # ── NORMAL ────────────────────────────────────────────────────────────────
    "android.permission.INTERNET": {
        "level": "NORMAL",
        "reason": "Full internet access — benign alone, but enables exfiltration in combination.",
    },
    "android.permission.VIBRATE": {
        "level": "NORMAL",
        "reason": "Trigger the device vibration motor.",
    },
    "android.permission.WAKE_LOCK": {
        "level": "NORMAL",
        "reason": "Prevent the CPU from sleeping — used by background services.",
    },
    "android.permission.ACCESS_NETWORK_STATE": {
        "level": "NORMAL",
        "reason": "Check whether a network connection is available.",
    },
    "android.permission.FOREGROUND_SERVICE": {
        "level": "NORMAL",
        "reason": "Run a persistent foreground service with a visible notification.",
    },
}

# ── Dangerous permission combinations ─────────────────────────────────────────
# Each entry is a tuple: (permission_a, permission_b, description_of_risk)
DANGEROUS_COMBINATIONS = [
    (
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
        "SMS Exfiltration: the app can read all SMS messages (including OTP/2FA codes) "
        "and transmit them to a remote server.",
    ),
    (
        "android.permission.RECORD_AUDIO",
        "android.permission.INTERNET",
        "Audio Surveillance: the app can record microphone audio silently and upload "
        "recordings to a remote server.",
    ),
    (
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.INTERNET",
        "Location Tracking: the app can obtain precise GPS coordinates and transmit "
        "them continuously to a remote server.",
    ),
    (
        "android.permission.READ_CONTACTS",
        "android.permission.INTERNET",
        "Contact Harvesting: the app can read the full contacts list and upload it "
        "to a remote server.",
    ),
    (
        "android.permission.CAMERA",
        "android.permission.INTERNET",
        "Remote Camera Surveillance: the app can take photos or video silently "
        "and upload them to a remote server.",
    ),
    (
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.INTERNET",
        "Keylogging/Overlay Attack: an accessibility service can observe and capture "
        "all screen content and user input, then relay it to a remote server.",
    ),
    (
        "android.permission.READ_CALL_LOG",
        "android.permission.INTERNET",
        "Call Log Exfiltration: the app can read the full call history and transmit "
        "it to a remote server.",
    ),
]

# ── Severity scoring weights ──────────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH":     15,
    "MEDIUM":    5,
    "LOW":       1,
    "INFO":      0,
}

# ── Groq / Application settings loaded from .env ─────────────────────────────
GROQ_API_KEY     = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL       = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
APP_NAME         = os.getenv("APP_NAME", "APK Security Intelligence Platform")
MAX_APK_SIZE_MB  = int(os.getenv("MAX_APK_SIZE_MB", "100"))
FRONTEND_URL     = os.getenv("FRONTEND_URL", "http://localhost:5173")

MAX_APK_SIZE_BYTES = MAX_APK_SIZE_MB * 1024 * 1024
