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

# Define administrator / operator IPs to protect from self-banning
OWN_IPS = {"127.0.0.1", "YOUR_ADMIN_IP_HERE"}

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
MIN_EVENTS_FOR_AI = 3

# ---------------- Rate Limiting ----------------
# Hard cap imposed by the NIM free tier is 40 RPM. We run at a 50% safety
# margin (20 RPM) so a burst from another process sharing this key, or a
# noisy scan sweep, never trips the provider's limiter.
MAX_REQUESTS_PER_MINUTE = 20
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


def query_ai(ip, events, total_requests, error_count):
    if client is None:
        logger.error(f"Skipping AI evaluation for {ip}: no API key configured")
        return None

    context = "\n".join(events[-10:])
    prompt = f"""Analyze the following Nginx security log context for IP address {ip}:

Traffic Summary:
- Total Logged Events: {total_requests}
- HTTP Error Count (4xx/5xx): {error_count}

Recent Log Entries:
{context}

System Directive:
Identify if this IP is performing automated scanning, path traversal, exploit injection (SQLi/XSS/RCE), sensitive file probing, or credential attack.

Respond strictly with BAN, IGNORE, or UNBAN."""

    system_prompt = (
        "You are an automated Web Application Firewall (WAF) analyzer. "
        "Your role is to classify traffic into BAN, IGNORE, or UNBAN with absolute precision."
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

            logger.info(f"AI evaluated {ip} (Errors={error_count}/{total_requests}): decision={decision} (raw='{raw_resp}')")
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

    candidate_ips = set()
    for ip, events in suspicious_events_by_ip.items():
        if len(events) >= MIN_EVENTS_FOR_AI:
            candidate_ips.add(ip)

    for ip, err_count in error_counts_by_ip.items():
        if err_count >= MIN_EVENTS_FOR_AI:
            candidate_ips.add(ip)

    logger.info(f"Identified {len(candidate_ips)} candidate IPs for AI evaluation")

    if len(candidate_ips) > MAX_REQUESTS_PER_MINUTE:
        eta_seconds = (len(candidate_ips) / MAX_REQUESTS_PER_MINUTE) * 60
        logger.info(
            f"{len(candidate_ips)} candidates exceed the {MAX_REQUESTS_PER_MINUTE} RPM budget; "
            f"this sweep will take roughly {eta_seconds:.0f}s to fully evaluate"
        )

    for ip in candidate_ips:
        events_to_show = suspicious_events_by_ip[ip] if suspicious_events_by_ip[ip] else all_events_by_ip[ip]
        total_reqs = len(all_events_by_ip[ip])
        err_count = error_counts_by_ip[ip]

        decision = query_ai(ip, events_to_show, total_reqs, err_count)
        if decision == "BAN":
            ban_ip(ip, f"AI decision triggered (Total Reqs: {total_reqs}, Errors: {err_count})")
        elif decision == "UNBAN":
            unban_ip(ip)

    logger.info("Watchdog execution finished")


if __name__ == "__main__":
    main()
