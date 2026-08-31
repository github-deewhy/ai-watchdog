#!/usr/bin/env bash
#
# fail2ban-report.sh
# Prints a formatted, human-readable summary of every fail2ban jail:
# status, failure counts, and currently banned IPs.
#
# Usage: sudo ./fail2ban-report.sh

set -euo pipefail

if ! command -v fail2ban-client >/dev/null 2>&1; then
    echo "Error: fail2ban-client not found. Is fail2ban installed?" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Error: this script must be run as root (sudo)." >&2
    exit 1
fi

# Colors (disabled automatically if output isn't a terminal)
if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
    CYAN=$'\033[36m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
fi

HR="────────────────────────────────────────────────────────────"

# Extract the jail list from `fail2ban-client status`.
# Expected line format: "`- Jail list:\tjail1, jail2, jail3"
JAIL_LINE=$(fail2ban-client status | grep -i "Jail list")
JAILS=$(echo "$JAIL_LINE" | sed -E 's/.*Jail list:[[:space:]]*//' | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

if [[ -z "$JAILS" ]]; then
    echo "No active fail2ban jails found."
    exit 0
fi

JAIL_COUNT=$(echo "$JAILS" | wc -l)
TOTAL_BANNED=0

echo ""
echo "${BOLD}${CYAN}Fail2ban Jail Report${RESET}  ${DIM}$(date '+%Y-%m-%d %H:%M:%S %Z')${RESET}"
echo "${DIM}Active jails: ${JAIL_COUNT}${RESET}"
echo "$HR"

while IFS= read -r jail; do
    [[ -z "$jail" ]] && continue

    STATUS_OUTPUT=$(fail2ban-client status "$jail" 2>/dev/null) || {
        echo "${RED}Could not fetch status for jail: $jail${RESET}"
        echo "$HR"
        continue
    }

    # Each extraction is tolerant of a missing field (`|| true`), since jail
    # output shape varies: e.g. a systemd/journald-backed jail (common for
    # `sshd` on Debian 13, which has no flat auth.log by default) prints
    # "Journal matches:" instead of "File list:". Without this tolerance,
    # a single missing field would kill the whole script under `set -e`.
    CURR_FAILED=$(echo "$STATUS_OUTPUT" | grep "Currently failed" | sed -E 's/.*:\s*//' || true)
    TOTAL_FAILED=$(echo "$STATUS_OUTPUT" | grep "Total failed"     | sed -E 's/.*:\s*//' || true)
    FILE_LIST=$(echo "$STATUS_OUTPUT"    | grep -E "File list|Journal matches" | sed -E 's/.*:\s*//' || true)
    CURR_BANNED=$(echo "$STATUS_OUTPUT"  | grep "Currently banned" | sed -E 's/.*:\s*//' || true)
    TOTAL_BANNED_JAIL=$(echo "$STATUS_OUTPUT" | grep "Total banned" | sed -E 's/.*:\s*//' || true)
    BANNED_IPS=$(echo "$STATUS_OUTPUT"   | grep "Banned IP list"   | sed -E 's/.*:\s*//' || true)

    TOTAL_BANNED=$((TOTAL_BANNED + ${CURR_BANNED:-0}))

    if [[ "${CURR_BANNED:-0}" -gt 0 ]]; then
        JAIL_COLOR="$YELLOW"
    else
        JAIL_COLOR="$GREEN"
    fi

    echo "${BOLD}${JAIL_COLOR}● ${jail}${RESET}"
    echo "  ${DIM}Watching:${RESET}        ${FILE_LIST:-n/a}"
    echo "  ${DIM}Failures (curr/total):${RESET} ${CURR_FAILED:-0} / ${TOTAL_FAILED:-0}"
    echo "  ${DIM}Banned (curr/total):${RESET}   ${JAIL_COLOR}${CURR_BANNED:-0}${RESET} / ${TOTAL_BANNED_JAIL:-0}"

    if [[ -n "${BANNED_IPS// /}" ]]; then
        echo "  ${DIM}Banned IPs:${RESET}"
        for ip in $BANNED_IPS; do
            echo "      ${RED}- ${ip}${RESET}"
        done
    else
        echo "  ${DIM}Banned IPs:${RESET}      ${GREEN}none${RESET}"
    fi

    echo "$HR"
done <<< "$JAILS"

echo "${BOLD}Summary:${RESET} ${JAIL_COUNT} jail(s) checked, ${BOLD}${TOTAL_BANNED}${RESET} IP(s) currently banned across all jails."
echo ""
