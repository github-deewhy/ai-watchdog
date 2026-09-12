# AI-Driven Nginx Security Watchdog for Fail2ban

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-1.2.0-informational.svg)

🌐 **Live demo & landing page:** [wdog.deewhy.ovh](https://wdog.deewhy.ovh)

This repo currently tracks the NVIDIA-NIM-backed build. A second,
local-Ollama-backed build is planned as a separate track (see the
[Roadmap](#roadmap) section) — once live it will be linked from the
landing page above alongside this one, for anyone who wants classification
to happen fully on-box instead of against a hosted API.

A small, resource-conscious detection engine that complements static
`fail2ban` jails by sending suspicious Nginx traffic to a hosted LLM for
classification — catching stealthy scanners, path-traversal probes, and
exploit injection attempts that evade fixed regex rules. Decisions are
handed to `fail2ban-client`, which enforces bans at the kernel level via
`nftables`.

`fail2ban` is excellent at "5 failed logins in 60 seconds." It has no way
to reason about "this single request looks like a crafted RCE payload." This
project fills that gap without replacing anything you already have —
it adds one more jail, driven by a language model instead of a regex.

```
Nginx Access & Error Logs
         │
         ▼
   watchdog.py  (triggered on a timer)
   - Inode & offset tracking (only reads new lines since last run)
   - Exploit signature engine (LFI/RCE/SQLi/SSRF patterns)
   - 4xx/5xx error-rate metrics
         │
   [Candidate IPs flagged: N+ suspicious hits OR N+ HTTP errors]
         │
         ▼
   Hosted LLM (OpenAI-compatible chat completions API)
         │
   [Decision: BAN / IGNORE / UNBAN]
         │
         ▼
   fail2ban-client  →  ai-watchdog jail (action-only, no filter/regex)
         │
         ▼
   nftables  (kernel-level packet drop)
```

The `ai-watchdog` fail2ban jail intentionally has no filter or regex
(`filter =`, `logpath = /dev/null`). It exists purely to hold the ban
action and duration — detection happens entirely in `watchdog.py`, which
then calls `fail2ban-client banip` / `unbanip` directly.

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Package contents](#package-contents)
- [Installation](#installation)
- [Configuration reference](#configuration-reference)
- [Rate limiting design](#rate-limiting-design)
- [Interactive dashboard & JSON reporting](#interactive-dashboard--json-reporting)
- [Troubleshooting](#troubleshooting)
- [Verification checklist](#verification-checklist)
- [Maintenance commands](#maintenance-commands)
- [Security notes](#security-notes)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [Looking for a dashboard and reports, not just a jail?](#looking-for-a-dashboard-and-reports-not-just-a-jail)

## Features

- Real-time-ish tailing of local Nginx access/error logs (inode + byte
  offset tracked between runs — no re-reading, no external state store)
- A pattern-based pre-filter (LFI/RCE/SQLi/SSRF/scanner signatures) so the
  LLM only sees traffic worth a second opinion
- A sliding-window rate limiter that respects your AI provider's per-minute
  quota, including retries
- Bans and unbans enforced by `fail2ban` + `nftables`, not by the script
  itself — this project only ever decides, it never touches the firewall
  directly
- A formatted, all-jails status report (`fail2ban-report.sh`) so you can see
  this jail next to every other jail you already run
- **NEW:** JSON output mode for integration with external dashboards and monitoring tools
- **NEW:** Interactive HTML dashboard with real-time sync capabilities
- systemd timer + logrotate units included, ready to drop in

## Requirements

- A recent Debian- or Ubuntu-based Linux host with `nftables`-backed
  `fail2ban` (tested on Debian 13 "trixie" and Ubuntu 24.04 LTS)
- Python 3.10+
- `fail2ban` installed and active
- An API key for an OpenAI-compatible chat completions endpoint. The
  defaults in this repo target NVIDIA's hosted NIM API
  ([build.nvidia.com](https://build.nvidia.com), free tier available), but
  any OpenAI-compatible provider works — just change `NVIDIA_BASE_URL` and
  `NVIDIA_MODEL` in `watchdog.py`.
- **Optional:** A web browser and local HTTP server (e.g., `python3 -m http.server`) for the interactive dashboard

## Package contents

| File | Purpose |
| --- | --- |
| `watchdog.py` | Main detection + AI classification script |
| `ai-watchdog.service` | systemd oneshot unit that runs a single sweep |
| `ai-watchdog.timer` | systemd timer firing the service periodically |
| `ai-watchdog.env.example` | Template for your API key env file |
| `ai-watchdog.logrotate` | logrotate config for `/var/log/ai-watchdog.log` |
| `fail2ban-report.sh` | Formatted status report across all fail2ban jails (with JSON output) |
| `fail2ban-report.html` | Interactive HTML dashboard for visualizing threat intelligence |
| `LICENSE` | MIT license |
| `CHANGELOG.md` | Version history |

## Installation

### 1. Application files

```bash
sudo mkdir -p /opt/ai-watchdog /var/lib/ai-watchdog /etc/ai-watchdog
sudo cp watchdog.py /opt/ai-watchdog/
sudo chmod +x /opt/ai-watchdog/watchdog.py
```

### 2. Python environment

A dedicated virtualenv is used deliberately, to avoid conflicts with your
distro's apt-managed Python packages (see [Troubleshooting](#troubleshooting)).

```bash
sudo python3 -m venv /opt/ai-watchdog/venv
sudo /opt/ai-watchdog/venv/bin/pip install --upgrade pip
sudo /opt/ai-watchdog/venv/bin/pip install openai
```

### 3. API key

```bash
sudo cp ai-watchdog.env.example /etc/ai-watchdog/ai-watchdog.env
sudo chmod 600 /etc/ai-watchdog/ai-watchdog.env
sudo nano /etc/ai-watchdog/ai-watchdog.env   # paste your real API key
```

### 4. fail2ban jail

Add to `/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
banaction = nftables
banaction_allports = nftables
ignoreip = 127.0.0.1/8 YOUR_ADMIN_IP_HERE

[ai-watchdog]
enabled   = true
filter    =
port      = all
banaction = nftables-allports
logpath   = /dev/null
maxretry  = 1
findtime  = 1
bantime   = 86400
```

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status ai-watchdog   # should show the jail, 0 banned
```

### 5. systemd service + timer

```bash
sudo cp ai-watchdog.service ai-watchdog.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start ai-watchdog.service   # manual dry run
sudo tail -n 20 /var/log/ai-watchdog.log   # confirm no errors
sudo systemctl enable --now ai-watchdog.timer
systemctl list-timers ai-watchdog.timer    # confirm NEXT/LEFT is populated
```

Only the `.timer` is enabled. `ai-watchdog.service` has no `[Install]`
section by design — it's triggered by the timer, not meant to be enabled
or started at boot directly.

### 6. Log rotation

```bash
sudo cp ai-watchdog.logrotate /etc/logrotate.d/ai-watchdog
sudo chmod 644 /etc/logrotate.d/ai-watchdog
sudo logrotate -d /etc/logrotate.d/ai-watchdog   # dry run, sanity check
```

Rotates weekly or at 20MB (whichever comes first), keeps 8 compressed
copies. No `copytruncate` needed — `watchdog.py` opens the log fresh on
every run rather than holding a persistent file handle, so standard
rename-based rotation is safe.

### 7. Jail status utility

```bash
sudo cp fail2ban-report.sh /usr/local/bin/fail2ban-report.sh
sudo chmod +x /usr/local/bin/fail2ban-report.sh
sudo fail2ban-report.sh
```

Prints a formatted summary of every active fail2ban jail — watched
log/journal source, failure counts, currently banned IPs, and a running
total across all jails. Reads the jail list dynamically, so it picks up
new jails automatically. Colors auto-disable when output isn't a terminal
(e.g. redirected to a file or cron mail).

**JSON output mode:**

```bash
sudo fail2ban-report.sh --json                    # saves to f2b_status.json
sudo fail2ban-report.sh --json custom_output.json # saves to custom filename
```

Generates a structured JSON file containing all jail metrics, banned IPs,
and geolocation data. Perfect for integration with external dashboards,
SIEM systems, or automated reporting pipelines.

### 8. Interactive dashboard (optional)

```bash
sudo cp fail2ban-report.html /var/www/html/
# OR serve locally:
cd /path/to/dashboard
python3 -m http.server 8000
```

Open your browser to `http://localhost:8000/fail2ban-report.html` (or your
configured path). On load — and whenever you click **🔄 Sync Data** — the
dashboard fetches `f2b_status.json` from the same directory and provides:

- Real-time KPI metrics (active bans, blocked attempts, geographic distribution)
- Interactive charts (jail enforcement metrics, attacker geography)
- Comprehensive IP correlation matrix with quick-unban commands
- Deterministic technical evaluation and hardening recommendations
- Manual sync button to refresh data without reloading the page

**Dashboard features:**

- **Dual-mode data loading:** Automatic HTTP fetch (when served via web server) or manual file upload
- **Filtered view:** Focuses exclusively on the `ai-watchdog` jail for clarity
- **Search & filter:** Quickly find specific IPs or countries in the banned IP registry
- **Zero hardcoded data:** Everything is dynamically generated from the JSON output

### 9. Before going live

- `watchdog.py` → `OWN_IPS`: replace `YOUR_ADMIN_IP_HERE` with this
  server's real admin IP(s), so you never self-ban.
- `jail.local` → `ignoreip`: same reason, on the fail2ban side.
- If your Nginx logs live somewhere other than `/var/log/nginx/`, update
  `NGINX_ACCESS_LOG` / `NGINX_ERROR_LOG` at the top of `watchdog.py`.

## Configuration reference

| Setting | File | Default | Notes |
| --- | --- | --- | --- |
| `NVIDIA_BASE_URL` / `NVIDIA_MODEL` | `watchdog.py` | NVIDIA NIM, `nvidia/nemotron-3-nano-30b-a3b` | Point at any OpenAI-compatible endpoint |
| `OWN_IPS` | `watchdog.py` | `{"127.0.0.1"}` | Admin/operator IPs excluded from banning |
| `MIN_EVENTS_FOR_AI` | `watchdog.py` | `3` | Minimum suspicious hits or HTTP errors before a candidate IP is sent to the AI |
| `MAX_REQUESTS_PER_MINUTE` | `watchdog.py` | `20` | Hard cap on outbound AI calls per minute |
| `MAX_RETRIES` | `watchdog.py` | `4` | Retry attempts on 429/connection errors, exponential backoff |
| Timer cadence | `ai-watchdog.timer` | every 5 minutes | `OnCalendar=*:0/5` |
| `bantime` | `jail.local` | `86400` (24h) | How long an IP stays banned |

## Rate limiting design

The script does not use a fixed `sleep()` between calls. It uses a
sliding-window limiter (`RateLimiter` class in `watchdog.py`): it tracks
the timestamp of every API call made in the last 60 seconds and blocks
before exceeding the configured per-minute budget. This is stricter than
fixed spacing because it also absorbs bursts (e.g. an overlapping manual
run), and every retry attempt — not just the first try — counts against
the budget, so backoff loops can't quietly exceed your quota.

## Interactive dashboard & JSON reporting

The project now includes a comprehensive visualization layer for monitoring
your AI-driven security posture:

**JSON output format:**

```json
{
  "timestamp": "2026-09-11 16:33:24 CEST",
  "total_jails": 10,
  "totals": {
    "currently_banned": 65,
    "total_banned": 76,
    "currently_failed": 0,
    "total_failed": 320
  },
  "jails": [
    {
      "name": "ai-watchdog",
      "status": "active",
      "currently_banned": 55,
      "total_banned": 56,
      "currently_failed": 0,
      "total_failed": 0,
      "log_files": ["/dev/null"],
      "banned_ips": [
        { "ip": "101.36.127.131", "country": "HK" },
        { "ip": "130.12.180.117", "country": "US" }
      ]
    }
  ]
}
```

**Dashboard capabilities:**

- **Geolocation tracking:** Automatic IP-to-country mapping via `geoiplookup`
- **Multi-vector detection:** Identifies IPs banned across multiple jails
- **Infrastructure analysis:** Highlights cloud provider ranges (GCP, DigitalOcean, OVH, AWS)
- **Threat correlation:** Cross-references jail activity to reveal persistent botnet nodes
- **Actionable insights:** Deterministic technical evaluation with hardening recommendations

**Deployment options:**

1. **Local development:** `python3 -m http.server 8000` in the directory containing `fail2ban-report.html` and `f2b_status.json`
2. **Production web server:** Place both files in your web root (e.g., `/var/www/html/`)
3. **Cron-based refresh:** Add `*/5 * * * * /usr/local/bin/fail2ban-report.sh --json /var/www/html/f2b_status.json` to automatically regenerate the JSON every 5 minutes, so the dashboard always has fresh data waiting the next time someone opens it or hits **🔄 Sync Data**

## Troubleshooting

### `pip install openai` fails with `uninstall-no-record-file`

This happens because `openai`'s dependency `typing_extensions` is already
installed by apt, and apt-installed packages don't carry pip's `RECORD`
metadata, so pip refuses to safely upgrade/uninstall it. Fix: use the
dedicated venv described in step 2 instead of installing into system
Python — this sidesteps the conflict entirely rather than forcing past it.

### `HTTP 404` or `400 ... DEGRADED function cannot be invoked`

Freshly released models on a provider's hosted free tier can be unstable
right after launch. If you hit this, switch `NVIDIA_MODEL` to a model
that's been stable in production for a while, and check your provider's
status page before assuming a config problem.

### `ModuleNotFoundError: No module named 'openai'` from systemd

Usually one of:

- `openai` was never actually installed — verify with
  `sudo /opt/ai-watchdog/venv/bin/pip show openai`.
- `ai-watchdog.service`'s `ExecStart` still points at `/usr/bin/python3`
  instead of `/opt/ai-watchdog/venv/bin/python3` — check with
  `grep ExecStart /etc/systemd/system/ai-watchdog.service`.

### Dashboard shows "Failed to fetch f2b_status.json"

This is expected when opening `fail2ban-report.html` directly via `file://`
protocol. Modern browsers block cross-origin requests from local files for
security — the dashboard's auto-fetch and **🔄 Sync Data** button only work
when the page is served over HTTP.

**Solutions:**

1. Serve via HTTP: `python3 -m http.server 8000` then visit
   `http://localhost:8000/fail2ban-report.html`
2. Use the "📁 Load JSON" button to manually select a `f2b_status.json`
   file you generated with `fail2ban-report.sh --json`
3. Ensure `f2b_status.json` exists in the same directory as
   `fail2ban-report.html` — the dashboard fetches it by that exact
   relative path (`./f2b_status.json`), so a different filename or
   folder needs the manual upload button instead

### Forcing a manual end-to-end test

Real scan traffic is sporadic; to verify the whole pipeline on demand:

```bash
# RFC 5737 reserved test address — safe to use, not a real host
echo '203.0.113.99 - - [DD/Mon/YYYY:HH:MM:SS +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "test-agent"' \
  | sudo tee -a /var/log/nginx/access.log

sudo sed -i 's/^MIN_EVENTS_FOR_AI = 3/MIN_EVENTS_FOR_AI = 1/' /opt/ai-watchdog/watchdog.py
sudo systemctl restart ai-watchdog.service
sudo tail -n 10 /var/log/ai-watchdog.log

# Clean up afterward
sudo fail2ban-client set ai-watchdog unbanip 203.0.113.99
sudo sed -i 's/^MIN_EVENTS_FOR_AI = 1/MIN_EVENTS_FOR_AI = 3/' /opt/ai-watchdog/watchdog.py
sudo systemctl restart ai-watchdog.service
```

## Verification checklist

```bash
grep ExecStart /etc/systemd/system/ai-watchdog.service   # venv python path
systemctl is-enabled ai-watchdog.timer fail2ban           # both "enabled"
systemctl list-timers ai-watchdog.timer                   # NEXT time populated
sudo fail2ban-client status ai-watchdog                    # jail exists
sudo /opt/ai-watchdog/venv/bin/pip show openai             # installed in venv
sudo tail -n 20 /var/log/ai-watchdog.log                   # clean runs, no tracebacks
sudo fail2ban-report.sh --json                             # JSON output works
ls -la f2b_status.json                                     # JSON file created
```

## Maintenance commands

```bash
sudo fail2ban-client status ai-watchdog        # active bans
sudo tail -f /var/log/ai-watchdog.log          # live AI decisions
sudo nft list table inet f2b-table             # kernel firewall state
sudo fail2ban-client set ai-watchdog unbanip <IP>
sudo fail2ban-report.sh                        # formatted CLI report
sudo fail2ban-report.sh --json                 # generate JSON for dashboard
```

## Security notes

- `/etc/ai-watchdog/ai-watchdog.env` must stay `chmod 600`, root-owned —
  it holds your API key in plaintext.
- `ai-watchdog.service` runs with `NoNewPrivileges`, `ProtectSystem=strict`,
  and `ProtectHome=true`, with write access limited to `/var/lib/ai-watchdog`
  and `/var/log`.
- Always keep your own admin IP(s) in both `OWN_IPS` (in `watchdog.py`) and
  `ignoreip` (in `jail.local`) to avoid self-lockout.
- This tool only ever calls `fail2ban-client banip`/`unbanip`; it never
  edits `nftables` rules, `iptables`, or any config file on your host
  directly. Firewall enforcement stays entirely inside `fail2ban`, which
  you already control.
- Log contents (including request paths and user agents) are sent to
  whichever AI provider you configure. Review that provider's data-handling
  terms before pointing this at logs that may contain sensitive data.
- The JSON output file (`f2b_status.json`) contains IP addresses and
  geolocation data. Ensure appropriate file permissions if deploying the
  dashboard on a public-facing web server.

## Contributing

Issues and pull requests are welcome. Please open an issue describing the
change before submitting a larger PR, and keep new detection patterns or
provider integrations behind the existing config surface (env vars /
constants at the top of `watchdog.py`) rather than hardcoding them deeper
in the script.

## Roadmap

This project ships as two independent build tracks against the same
`watchdog.py` core, differing only in where classification happens:

| Track | Status | Classification runs | Notes |
| --- | --- | --- | --- |
| NVIDIA NIM (this repo, `main`) | Live | Hosted API (`build.nvidia.com`) | Free tier available, no local GPU needed |
| Local Ollama | Planned | On-box, fully offline | For deployments that can't send log data off-host |

Both tracks will be linked from [wdog.deewhy.ovh](https://wdog.deewhy.ovh)
once the Ollama build is published; until then this README and repo cover
the NVIDIA track only.

## Looking for a dashboard and reports, not just a jail?

This project is deliberately minimal: a script, a timer, and a fail2ban
jail — no UI, no history, no compliance reports. If you want a visual
dashboard over your Nginx security data — trend charts, a top-adversary
table, per-incident forensic drill-down, and audit-ready SOC 2 / NIST CSF
style reports generated by your choice of local or cloud AI model — see
the companion AI Security Intelligence & Report Agent. It reads the
same Nginx logs this project does, but as a reporting/monitoring layer
rather than an enforcement one (it never touches your firewall either —
it only ever generates copy-pasteable remediation commands).

**Note:** This repo now includes `fail2ban-report.html`, a lightweight
interactive dashboard focused on the `ai-watchdog` jail. It's fed by a
static JSON snapshot, not a live backend, so getting data into it is a
two-step, no-server-code process:

1. **Export a snapshot** — run the reporting script in JSON mode wherever
   `fail2ban-report.sh` lives, pointed at the same directory as the
   dashboard file:

   ```bash
   sudo fail2ban-report.sh --json /var/www/html/f2b_status.json
   ```

2. **Feed the dashboard** — open `fail2ban-report.html` (served over
   HTTP, e.g. `http://localhost:8000/fail2ban-report.html`) and either let
   it auto-load `f2b_status.json` from the same folder, click
   **🔄 Sync Data** to re-fetch after a fresh export, or use
   **📁 Load JSON** to pick a snapshot file by hand — the last option
   also works when double-clicking the HTML file locally via `file://`,
   which blocks the automatic fetch.

For a snapshot that updates itself, add step 1 to cron (see
[Deployment options](#interactive-dashboard--json-reporting)) so the file
`fail2ban-report.html` reads is never more than a few minutes stale.

For comprehensive multi-jail analytics, historical trending, and
compliance reporting beyond this single-jail snapshot view, the companion
tool remains the recommended choice.

## License

MIT — see [LICENSE](./LICENSE).
