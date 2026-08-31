# Changelog

This project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`):

- **MAJOR** — breaking changes (env var renames/removals, jail/config format changes)
- **MINOR** — backward-compatible feature additions (new detection signals, new utilities)
- **PATCH** — backward-compatible fixes (bug fixes, security patches, dependency bumps)

## [1.1.0] - 2026-08-28

- Added a `logrotate` config for `/var/log/ai-watchdog.log`.
- Added `fail2ban-report.sh`, a formatted, all-jails status utility.

## [1.0.0] - 2026-08-28

- First production release: hosted-LLM backend, systemd timer orchestration,
  sliding-window rate limiter, verified end-to-end with a live test ban/unban.

> Pre-1.0 history (local-LLM + cron prototype) predates this repository and
> is not version-tracked here.
