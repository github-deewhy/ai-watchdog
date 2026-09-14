# Changelog

This project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`):

- **MAJOR** — breaking changes (env var renames/removals, jail/config format changes)
- **MINOR** — backward-compatible feature additions (new detection signals, new utilities)
- **PATCH** — backward-compatible fixes (bug fixes, security patches, dependency bumps)

## [1.3.0] - 2026-09-13

### Fixed

- **Admin self-banning:** `watchdog.py` previously shipped with a literal
  `YOUR_ADMIN_IP_HERE` placeholder in `OWN_IPS` that was easy to leave
  unreplaced. Because `watchdog.py` bans by calling `fail2ban-client set
  ai-watchdog banip <ip>` directly, the jail's `ignoreip` setting does
  **not** protect against this — `ignoreip` only applies to fail2ban's own
  filter-driven jails, not to manual/API-issued ban commands. An operator
  could be correctly whitelisted in `jail.local` and still get banned by
  the watchdog itself. Admin IPs are now supplied via a required `ADMIN_IPS`
  env var instead of a hardcoded placeholder, and a warning is logged on
  every run if it's left unset.
- **Env file path inconsistency:** `ai-watchdog.service`'s `EnvironmentFile`
  and the installation docs previously disagreed with each other in some
  deployments about whether the env file lives under `/etc/ai-watchdog/`
  or `/opt/ai-watchdog/`. Standardized on `/opt/ai-watchdog/ai-watchdog.env`
  (alongside `watchdog.py` itself) everywhere — the service unit, the env
  example header comment, and the README installation steps.

### Added

- `ADMIN_IPS` env var (`ai-watchdog.env`): comma/whitespace-separated list
  of admin/operator IPs, merged with `127.0.0.1`, exempted from banning.
- Adjustable detection thresholds, all overridable via env vars so tuning
  no longer requires editing `watchdog.py`:
  - `AI_WATCHDOG_MIN_SUSPICIOUS_EVENTS` (default `3`)
  - `AI_WATCHDOG_MIN_ERROR_COUNT` (default `15`)
  - `AI_WATCHDOG_MIN_ERROR_RATE` (default `0.6`)
  - `AI_WATCHDOG_MIN_TOTAL_REQUESTS` (default `10`)
  - `AI_WATCHDOG_ALLOW_ERROR_ONLY_BAN` (default `false`)
  - `AI_WATCHDOG_MAX_RPM` (default `20`)
- Code-level guardrail: an IP flagged on HTTP error volume alone (no
  suspicious exploit/scanner pattern match) is never banned, even if the
  AI returns `BAN`, unless `AI_WATCHDOG_ALLOW_ERROR_ONLY_BAN=true`.

### Changed

- **Less aggressive error-based triggering:** an IP is now only sent to the
  AI on error grounds if it clears both a minimum error *count* and a
  minimum error *rate* (errors / total requests) over a minimum sample
  size — previously a raw count of 3 errors was enough, which could catch
  ordinary visitors browsing a site with a few broken links, missing
  assets, or in-progress pages.
- **Improved AI prompt:** the classification prompt now includes the
  computed error rate, explicitly names common benign causes of HTTP
  errors, and instructs the model to prefer `IGNORE` when evidence is
  ambiguous, reducing false-positive `BAN` decisions from the small
  classification model.
- Log lines for AI decisions now include the error rate and whether the
  candidate was flagged via suspicious patterns or error rate, to make
  after-the-fact review easier.

### Migration notes

- **Action required:** set `ADMIN_IPS` in `/opt/ai-watchdog/ai-watchdog.env`
  to your real admin/operator IP(s) before deploying this version. The old
  `OWN_IPS` hardcoded set in `watchdog.py` is no longer read from code —
  only `127.0.0.1` plus whatever `ADMIN_IPS` supplies is protected.
- If you had previously edited `MIN_EVENTS_FOR_AI` directly in
  `watchdog.py`, that constant has been split into the suspicious/error
  thresholds above — replicate your old value via
  `AI_WATCHDOG_MIN_SUSPICIOUS_EVENTS` and review the new error-rate
  defaults, which are intentionally stricter than the old raw count.

## [1.2.0] - 2026-09-12

### Added

- **JSON output mode for `fail2ban-report.sh`:** New `--json` flag generates structured JSON data containing all jail metrics, banned IPs with geolocation, and aggregate statistics. Perfect for integration with external dashboards, SIEM systems, or automated reporting pipelines.
- **Interactive HTML dashboard (`f2b.html`):** Comprehensive visualization layer for monitoring AI-driven security posture, featuring:
  - Real-time KPI metrics (active bans, blocked attempts, geographic distribution)
  - Interactive charts (jail enforcement metrics, attacker geography via Chart.js)
  - Comprehensive IP correlation matrix with quick-unban commands
  - Deterministic technical evaluation and hardening recommendations
  - Dual-mode data loading (automatic HTTP fetch or manual file upload)
  - Search and filter capabilities for the banned IP registry
  - Filtered view focusing exclusively on the `ai-watchdog` jail for clarity
- **Geolocation tracking:** Automatic IP-to-country mapping via `geoiplookup` integration in the report script
- **Multi-vector detection:** Dashboard identifies IPs banned across multiple jails
- **Infrastructure analysis:** Highlights cloud provider ranges (GCP, DigitalOcean, OVH, AWS) in threat evaluation

### Changed

- Enhanced `fail2ban-report.sh` to support optional output filename parameter
- Improved error handling in JSON generation for edge cases (missing fields, empty jail lists)
- Updated documentation with comprehensive dashboard deployment instructions

### Technical details

- JSON schema includes timestamp, total jail count, aggregate metrics, and per-jail breakdowns
- Dashboard uses zero hardcoded data — all metrics dynamically generated from JSON payload
- Automatic cache-busting on HTTP fetch to ensure fresh data on sync
- Graceful fallback when opened via `file://` protocol (manual file upload required)

## [1.1.0] - 2026-08-28

### Added

- Added a `logrotate` config for `/var/log/ai-watchdog.log`.
- Added `fail2ban-report.sh`, a formatted, all-jails status utility.

## [1.0.0] - 2026-08-28

### Added

First production release: hosted-LLM backend, systemd timer orchestration,
sliding-window rate limiter, verified end-to-end with a live test ban/unban.

Pre-1.0 history (local-LLM + cron prototype) predates this repository and
is not version-tracked here.
