#!/usr/bin/env python3
import os
import re
import json
import time
import threading
import subprocess
import logging
from collections import defaultdict, deque

from openai import OpenAI, APIStatusError, APIConnectionError

# ---------------- Configuration ----------------
NGINX_ACCESS_LOG = "/var/log/nginx/access.log"
NGINX_ERROR_LOG  = "/var/log/nginx/error.log"

# NVIDIA NIM (OpenAI-compatible) endpoint
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
NVIDIA_MODEL = "nvidia/nemotron-3-nano-30b-a3b"
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY")

JAIL = "ai-watchdog"
STATE_FILE = "/var/lib/ai-watchdog/state.json"
LOG_FILE = "/var/log/ai-watchdog.log"


def _parse_ip_list(raw):
    """Split a comma/whitespace-separated env value into a clean set of IPs."""
    if not raw:
        return set()
    return {ip.strip() for ip in re.split(r"[,\s]+", raw) if ip.strip()}


def _parse_bool(raw, default=False):
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _parse_float(raw, default):
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def _parse_int(raw, default):
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


# Administrator / operator IPs, protected from self-banning. Always includes
# localhost. Additional IPs come from the ADMIN_IPS env var (comma or
# whitespace separated), e.g.:
#   ADMIN_IPS=203.0.113.10,203.0.113.11
# Keep this in sync with `ignoreip` in jail.local — that setting protects
# you from fail2ban's own filter, this one protects you from watchdog.py's
# *direct* fail2ban-client banip calls, which do not consult jail ignoreip.
OWN_IPS = {"127.0.0.1"} | _parse_ip_list(os.environ.get("ADMIN_IPS"))

EXCLUDED_USER_AGENTS = [
    "CensysInspect", "Palo Alto Networks", "ClaudeBot", "OAI-SearchBot",
    "FlowIQLabsBot", "Infrawatch", "zgrab", "visionheight", "RecordedFuture",
    "CyberConvoyScout", "InternetMeasurement", "FreePBX-Scanner", "CT-WP-Probe"
]

SUSPICIOUS_PATTERNS = [
    r'wp-content', r'wp-includes', r'wp-config', r'wp-login', r'xmlrpc\.php',
    r'admin\.php', r'shell\.php', r'eval-stdin\.php', r'phpunit', r'phpinfo',
    r'actuator', r'terraform\.tfstate', r'\.env', r'\.git', r'\.aws', r'\.ssh',
    r'\.dockerenv', r'appsettings\.json', r'cgi-bin/',
    r'\.\./', r'%2e%2e', r'%32%65', r'etc/passwd', r'win\.ini', r'php://input',
    r'allow_url_include', r'auto_prepend_file',
    r'\$\{jndi:', r'cmd\.exe', r'/bin/sh', r'/bin/bash', r'exec\(', r'system\(',
    r'passthru\(', r'eval\(',
    r'union\s+select', r'information_schema', r'sleep\(\d+\)', r'waitfor\s+delay',
    r'select\s+.*\s+from', r'drop\s+table', r'insert\s+into',
    r'169\.254\.169\.254', r'metadata\.google\.internal',
    r'l9explore', r'libredtail', r'masscan', r'nikto', r'sqlmap', r'nmap'
]

HTTP_ERROR_STATUSES = {"400", "401", "403", "404", "405", "499", "500", "502", "503"}

# ---------------- Detection thresholds ----------------
# All overridable via env so tuning doesn't require touching code.
#
# Suspicious-pattern hits are a strong, low-noise signal (wp-login, .env,
# SQLi payloads etc. don't show up from normal browsing), so this stays low.
MIN_SUSPICIOUS_EVENTS_FOR_AI = _parse_int(os.environ.get("AI_WATCHDOG_MIN_SUSPICIOUS_EVENTS"), 3)

# Plain HTTP errors (404/403/etc.) are NOT a strong signal on their own —
# a few clicks around a freshly-deployed site, a missing favicon, or a
# typo'd URL will produce these too. To avoid flagging ordinary visitors,
# an IP must clear *both* a minimum error count AND a minimum error rate
# (errors / total requests) before it's sent to the AI on error grounds
# alone. Raise MIN_ERROR_EVENTS_FOR_AI and/or MIN_ERROR_RATE_FOR_AI if you
# are still seeing false positives from real traffic.
MIN_ERROR_EVENTS_FOR_AI = _parse_int(os.environ.get("AI_WATCHDOG_MIN_ERROR_COUNT"), 15)
MIN_ERROR_RATE_FOR_AI = _parse_float(os.environ.get("AI_WATCHDOG_MIN_ERROR_RATE"), 0.6)
MIN_TOTAL_REQUESTS_FOR_ERROR_RATE = _parse_int(os.environ.get("AI_WATCHDOG_MIN_TOTAL_REQUESTS"), 10)

# Code-level guardrail: an IP that only tripped the *error* threshold (no
# suspicious-pattern hits at all) will not be banned even if the AI says
# BAN, unless this is explicitly enabled. This protects against a small
# model over-indexing on "lots of 404s" as an attack signature when it's
# often just real, imperfect traffic. Suspicious-pattern-triggered
# candidates are never affected by this flag.
ALLOW_ERROR_ONLY_BAN = _parse_bool(os.environ.get("AI_WATCHDOG_ALLOW_ERROR_ONLY_BAN"), False)

# ---------------- Rate Limiting ----------------
# Hard cap imposed by the NIM free tier is 40 RPM. We run at a 50% safety
# margin (20 RPM) so a burst from another process sharing this key, or a
# noisy scan sweep, never trips the provider's limiter.
MAX_REQUESTS_PER_MINUTE = _parse_int(os.environ.get("AI_WATCHDOG_MAX_RPM"), 20)
_WINDOW_SECONDS = 60.0
MAX_RETRIES = 4
BACKOFF_BASE_SECONDS = 2.0


class RateLimiter:
    """
    Sliding-window limiter: keeps a timestamp for every call made in the
    last _WINDOW_SECONDS and blocks new calls once the window is full.
    This is stricter than a fixed "sleep(3s)" between calls because it
    also protects against bursts if this script is ever called more than
    once per cycle (e.g. a manual run overlapping the timer).
    """

    def __init__(self, max_per_window, window_seconds):
        self.max_per_window = max_per_window
        self.window_seconds = window_seconds
        self._calls = deque()
        self._lock = threading.Lock()

    def acquire(self):
        with self._lock:
            now = time.monotonic()
            # Drop timestamps that have aged out of the window
            while self._calls and now - self._calls[0] >= self.window_seconds:
                self._calls.popleft()

            if len(self._calls) >= self.max_per_window:
                # Wait until the oldest call in the window expires
                sleep_for = self.window_seconds - (now - self._calls[0])
                if sleep_for > 0:
                    logger.info(f"Rate limit guard: sleeping {sleep_for:.2f}s to stay under {self.max_per_window} req/min")
                    time.sleep(sleep_for)
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self.window_seconds:
                    self._calls.popleft()

            self._calls.append(time.monotonic())


rate_limiter = RateLimiter(MAX_REQUESTS_PER_MINUTE, _WINDOW_SECONDS)

# ---------------- Logging Setup ----------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("ai-watchdog")

if not OWN_IPS - {"127.0.0.1"}:
    logger.warning(
        "ADMIN_IPS is not set (or empty) — only 127.0.0.1 is protected from "
        "self-banning. Set ADMIN_IPS in the environment to your real IP(s) "
        "before relying on this in production."
    )

# ---------------- NVIDIA Client ----------------
client = None
if NVIDIA_API_KEY:
    client = OpenAI(base_url=NVIDIA_BASE_URL, api_key=NVIDIA_API_KEY)
else:
    logger.error("NVIDIA_API_KEY is not set in the environment. AI evaluation will be skipped.")


# ---------------- Helper Functions ----------------
def run_cmd(cmd):
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return proc.stdout.strip(), proc.stderr.strip(), proc.returncode


def ban_ip(ip, reason):
    cmd = f"fail2ban-client set {JAIL} banip {ip}"
    out, err, rc = run_cmd(cmd)
    if rc == 0:
        logger.info(f"Banned {ip}: {reason}")
    else:
        logger.error(f"Failed to ban {ip}: {err}")


def unban_ip(ip):
    cmd = f"fail2ban-client set {JAIL} unbanip {ip}"
    out, err, rc = run_cmd(cmd)
    if rc == 0:
        logger.info(f"Unbanned {ip}")
    else:
        logger.error(f"Failed to unban {ip}: {err}")


def is_suspicious_line(line):
    if any(re.search(pattern, line, re.IGNORECASE) for pattern in SUSPICIOUS_PATTERNS):
        if any(ua.lower() in line.lower() for ua in EXCLUDED_USER_AGENTS):
            return False
        return True
    return False


def extract_ip(line):
    parts = line.split()
    if parts and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parts[0]):
        return parts[0]
    m = re.search(r'client:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
    if m:
        return m.group(1)
    return None


def extract_status_code(line):
    m = re.search(r'"\s+([1-5]\d\d)\s+', line)
    if m:
        return m.group(1)
    return None


def query_ai(ip, events, total_requests, error_count, has_suspicious_hits):
    if client is None:
        logger.error(f"Skipping AI evaluation for {ip}: no API key configured")
        return None

    error_rate = (error_count / total_requests) if total_requests else 0.0
    context = "\n".join(events[-10:])

    signal_note = (
        "This IP matched known exploit/scanner signatures (path traversal, "
        "credential/config probing, injection payloads, etc.) in its request "
        "paths."
        if has_suspicious_hits else
        "This IP was flagged purely on HTTP error volume/rate — no exploit "
        "or scanner signature matched any of its request paths."
    )

    prompt = f"""Analyze the following Nginx security log context for IP address {ip}:

Traffic Summary:
- Total Logged Events: {total_requests}
- HTTP Error Count (4xx/5xx): {error_count}
- HTTP Error Rate: {error_rate:.0%}
- Flag basis: {signal_note}

Recent Log Entries:
{context}

Important context: occasional HTTP errors (missing favicon/assets, a typo'd
URL, a page still under construction, normal manual QA browsing) are NOT
malicious on their own, even in a small sample. Only classify BAN when the
log entries show a clear attack signature: automated scanning across many
paths, path traversal, exploit injection (SQLi/XSS/RCE/SSRF), sensitive
file/credential probing, or a credential-stuffing pattern. If the evidence
is ambiguous or looks like it could plausibly be a real visitor or a normal
crawler, prefer IGNORE — a missed detection is cheap (it will be
re-evaluated next cycle if the behavior continues), but banning a real
visitor is not.

Respond strictly with BAN, IGNORE, or UNBAN."""

    system_prompt = (
        "You are an automated Web Application Firewall (WAF) analyzer. "
        "Your role is to classify traffic into BAN, IGNORE, or UNBAN with "
        "high precision, favoring IGNORE whenever the evidence is ambiguous "
        "rather than assuming malicious intent from limited data."
    )

    for attempt in range(1, MAX_RETRIES + 1):
        # Block here (not just before the try) so every attempt, including
        # retries, is counted against the 20 RPM budget.
        rate_limiter.acquire()
        try:
            completion = client.chat.completions.create(
                model=NVIDIA_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                max_tokens=16,
                # This is a fast deterministic classification task, not open-ended
                # reasoning, so extended thinking is disabled to save latency/tokens.
                extra_body={"chat_template_kwargs": {"enable_thinking": False}},
                stream=False,
            )

            raw_resp = (completion.choices[0].message.content or "").strip().upper()
            match = re.search(r'\b(BAN|IGNORE|UNBAN)\b', raw_resp)
            decision = match.group(1) if match else None

            logger.info(
                f"AI evaluated {ip} (Errors={error_count}/{total_requests}, "
                f"rate={error_rate:.0%}, suspicious={has_suspicious_hits}): "
                f"decision={decision} (raw='{raw_resp}')"
            )
            return decision

        except APIStatusError as e:
            if e.status_code == 429:
                backoff = BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                logger.error(f"Rate limited by NVIDIA API for {ip} (attempt {attempt}/{MAX_RETRIES}); backing off {backoff:.1f}s")
                time.sleep(backoff)
                continue
            logger.error(f"AI query failed for {ip}: HTTP {e.status_code} {e.message}")
            return None
        except APIConnectionError as e:
            backoff = BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
            logger.error(f"Connection error querying AI for {ip} (attempt {attempt}/{MAX_RETRIES}): {e}; retrying in {backoff:.1f}s")
            time.sleep(backoff)
            continue
        except Exception as e:
            logger.error(f"AI query failed for {ip}: {e}")
            return None

    logger.error(f"Exhausted retries querying AI for {ip}; skipping this cycle")
    return None


# ---------------- Cursor Management ----------------
def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read state file: {e}")
    return {}


def save_state(state):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception as e:
        logger.error(f"Failed to save state file: {e}")


def read_new_lines(filepath, state):
    if not os.path.exists(filepath):
        return []

    file_stat = os.stat(filepath)
    inode = file_stat.st_ino
    file_size = file_stat.st_size

    file_state = state.get(filepath, {})
    last_inode = file_state.get("inode")
    last_offset = file_state.get("offset", 0)

    if last_inode != inode or file_size < last_offset:
        last_offset = 0

    lines = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last_offset)
            for line in f:
                lines.append(line.strip())
            new_offset = f.tell()

        state[filepath] = {
            "inode": inode,
            "offset": new_offset
        }
    except Exception as e:
        logger.error(f"Error reading file {filepath}: {e}")

    return lines


# ---------------- Main Logic ----------------
def main():
    logger.info("Watchdog execution started")
    state = load_state()
    new_lines = []

    for logfile in [NGINX_ACCESS_LOG, NGINX_ERROR_LOG]:
        new_lines.extend(read_new_lines(logfile, state))

    save_state(state)

    logger.info(f"Read {len(new_lines)} new log lines")

    if not new_lines:
        logger.info("No new log entries to process. Exiting.")
        return

    all_events_by_ip = defaultdict(list)
    suspicious_events_by_ip = defaultdict(list)
    error_counts_by_ip = defaultdict(int)

    for line in new_lines:
        if not line:
            continue
        ip = extract_ip(line)
        if not ip or ip in OWN_IPS:
            continue

        all_events_by_ip[ip].append(line)

        status_code = extract_status_code(line)
        if status_code in HTTP_ERROR_STATUSES:
            error_counts_by_ip[ip] += 1

        if is_suspicious_line(line):
            suspicious_events_by_ip[ip].append(line)

    # An IP can be flagged two ways:
    #   1. Suspicious-pattern hits (strong signal, low threshold)
    #   2. HTTP error volume AND rate both crossing their thresholds
    #      (weak signal on its own, so both conditions are required)
    candidate_ips = set()
    error_only_ips = set()

    for ip, events in suspicious_events_by_ip.items():
        if len(events) >= MIN_SUSPICIOUS_EVENTS_FOR_AI:
            candidate_ips.add(ip)

    for ip, err_count in error_counts_by_ip.items():
        if ip in candidate_ips:
            continue  # already flagged via suspicious patterns
        total = len(all_events_by_ip[ip])
        error_rate = (err_count / total) if total else 0.0
        if (
            err_count >= MIN_ERROR_EVENTS_FOR_AI
            and total >= MIN_TOTAL_REQUESTS_FOR_ERROR_RATE
            and error_rate >= MIN_ERROR_RATE_FOR_AI
        ):
            candidate_ips.add(ip)
            error_only_ips.add(ip)

    logger.info(
        f"Identified {len(candidate_ips)} candidate IPs for AI evaluation "
        f"({len(candidate_ips) - len(error_only_ips)} via suspicious patterns, "
        f"{len(error_only_ips)} via error rate)"
    )

    if len(candidate_ips) > MAX_REQUESTS_PER_MINUTE:
        eta_seconds = (len(candidate_ips) / MAX_REQUESTS_PER_MINUTE) * 60
        logger.info(
            f"{len(candidate_ips)} candidates exceed the {MAX_REQUESTS_PER_MINUTE} RPM budget; "
            f"this sweep will take roughly {eta_seconds:.0f}s to fully evaluate"
        )

    for ip in candidate_ips:
        has_suspicious_hits = ip not in error_only_ips
        events_to_show = suspicious_events_by_ip[ip] if suspicious_events_by_ip[ip] else all_events_by_ip[ip]
        total_reqs = len(all_events_by_ip[ip])
        err_count = error_counts_by_ip[ip]

        decision = query_ai(ip, events_to_show, total_reqs, err_count, has_suspicious_hits)

        if decision == "BAN":
            if ip in error_only_ips and not ALLOW_ERROR_ONLY_BAN:
                logger.info(
                    f"AI said BAN for {ip} but it was flagged on error rate "
                    f"alone (no suspicious pattern match); withholding ban "
                    f"per ALLOW_ERROR_ONLY_BAN=false guardrail."
                )
                continue
            ban_ip(ip, f"AI decision triggered (Total Reqs: {total_reqs}, Errors: {err_count})")
        elif decision == "UNBAN":
            unban_ip(ip)

    logger.info("Watchdog execution finished")


if __name__ == "__main__":
    main()
