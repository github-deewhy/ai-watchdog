# Changelog

This project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`):

- **MAJOR** — breaking changes (env var renames/removals, jail/config format changes)
- **MINOR** — backward-compatible feature additions (new detection signals, new utilities)
- **PATCH** — backward-compatible fixes (bug fixes, security patches, dependency bumps)

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
