#!/usr/bin/env bash
#
# fail2ban-report.sh
# Prints a formatted, human-readable summary of every fail2ban jail:
# status, failure counts, and currently banned IPs.
#
# Usage: sudo ./fail2ban-report.sh [--json [output_file]]
set -euo pipefail

# Argument parsing for JSON mode
JSON_MODE=false
JSON_FILE="f2b_status.json"
while [[ $# -gt 0 ]]; do
    case $1 in
        -j|--json)
            JSON_MODE=true
            if [[ -n "$2" && "$2" != -* ]]; then
                JSON_FILE="$2"
                shift
            fi
            shift
            ;;
        *)
            shift
            ;;
    esac
done

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
JAIL_LINE=$(fail2ban-client status | grep -i "Jail list")
JAILS=$(echo "$JAIL_LINE" | sed -E 's/.*Jail list:[[:space:]]*//' | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

if [[ -z "$JAILS" ]]; then
    echo "No active fail2ban jails found."
    exit 0
fi

JAIL_COUNT=$(echo "$JAILS" | wc -l)

# GeoIP lookup function
geo_cc() {
    if command -v geoiplookup >/dev/null 2>&1; then
        local res
        res=$(geoiplookup "$1" 2>/dev/null | awk -F': ' '/GeoIP Country Edition/{print $2}' | cut -d, -f1 | xargs)
        if [[ -z "$res" || "$res" == "IP Address not found" ]]; then
            echo "--"
        else
            echo "$res"
        fi
    else
        echo "--"
    fi
}

# ==========================================
# JSON MODE OUTPUT
# ==========================================
if [[ "$JSON_MODE" == true ]]; then
    TOTAL_BANNED=0
    TOTAL_FAILED=0
    TOTAL_CURR_BANNED=0
    TOTAL_CURR_FAILED=0
    
    # First pass: collect all data
    declare -a JAIL_DATA=()
    while IFS= read -r jail; do
        [[ -z "$jail" ]] && continue
        
        STATUS_OUTPUT=$(fail2ban-client status "$jail" 2>/dev/null) || continue
        
        CURR_FAILED=$(echo "$STATUS_OUTPUT" | grep "Currently failed" | sed -E 's/.*:\s*//' || echo "0")
        TOTAL_FAILED=$(echo "$STATUS_OUTPUT" | grep "Total failed" | sed -E 's/.*:\s*//' || echo "0")
        FILE_LIST=$(echo "$STATUS_OUTPUT" | grep -E "File list|Journal matches" | sed -E 's/.*:\s*//' || echo "")
        CURR_BANNED=$(echo "$STATUS_OUTPUT" | grep "Currently banned" | sed -E 's/.*:\s*//' || echo "0")
        TOTAL_BANNED_JAIL=$(echo "$STATUS_OUTPUT" | grep "Total banned" | sed -E 's/.*:\s*//' || echo "0")
        BANNED_IPS=$(echo "$STATUS_OUTPUT" | grep "Banned IP list" | sed -E 's/.*:\s*//' || echo "")
        
        TOTAL_CURR_BANNED=$((TOTAL_CURR_BANNED + ${CURR_BANNED:-0}))
        TOTAL_BANNED=$((TOTAL_BANNED + ${TOTAL_BANNED_JAIL:-0}))
        TOTAL_CURR_FAILED=$((TOTAL_CURR_FAILED + ${CURR_FAILED:-0}))
        TOTAL_FAILED=$((TOTAL_FAILED + ${TOTAL_FAILED:-0}))
        
        # Build log files array
        logs_json="["
        first_log=true
        if [[ -n "$FILE_LIST" ]]; then
            for f in ${FILE_LIST//,/ }; do
                f=$(xargs <<<"$f")
                [[ -z "$f" ]] && continue
                [[ "$first_log" == false ]] && logs_json+=","
                first_log=false
                f_escaped="${f//\\/\\\\}"
                f_escaped="${f_escaped//\"/\\\"}"
                logs_json+="\"$f_escaped\""
            done
        fi
        logs_json+="]"
        
        # Build banned IPs array with geo data
        ips_json="["
        first_ip=true
        if [[ -n "${BANNED_IPS// /}" ]]; then
            for ip in $BANNED_IPS; do
                [[ "$first_ip" == false ]] && ips_json+=","
                first_ip=false
                cc=$(geo_cc "$ip")
                ips_json+="{\"ip\": \"$ip\", \"country\": \"$cc\"}"
            done
        fi
        ips_json+="]"
        
        status="idle"
        [[ ${CURR_BANNED:-0} -gt 0 ]] && status="active"
        
        jail_json="{"
        jail_json+="\"name\": \"$jail\","
        jail_json+="\"status\": \"$status\","
        jail_json+="\"currently_banned\": ${CURR_BANNED:-0},"
        jail_json+="\"total_banned\": ${TOTAL_BANNED_JAIL:-0},"
        jail_json+="\"currently_failed\": ${CURR_FAILED:-0},"
        jail_json+="\"total_failed\": ${TOTAL_FAILED:-0},"
        jail_json+="\"log_files\": $logs_json,"
        jail_json+="\"banned_ips\": $ips_json"
        jail_json+="}"
        
        JAIL_DATA+=("$jail_json")
    done <<< "$JAILS"
    
    # Build final JSON
    json="{"
    json+="\"timestamp\": \"$(date '+%Y-%m-%d %H:%M:%S %Z')\","
    json+="\"total_jails\": $JAIL_COUNT,"
    json+="\"totals\": {"
    json+="\"currently_banned\": $TOTAL_CURR_BANNED,"
    json+="\"total_banned\": $TOTAL_BANNED,"
    json+="\"currently_failed\": $TOTAL_CURR_FAILED,"
    json+="\"total_failed\": $TOTAL_FAILED"
    json+="},"
    json+="\"jails\": ["
    
    first_jail=true
    for jail_json in "${JAIL_DATA[@]}"; do
        [[ "$first_jail" == false ]] && json+=","
        first_jail=false
        json+="$jail_json"
    done
    
    json+="]}"
    
    echo "$json" > "$JSON_FILE"
    echo "✅ JSON data successfully saved to: $JSON_FILE" >&2
    exit 0
fi

# ==========================================
# STANDARD CLI OUTPUT (Original Logic)
# ==========================================
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
    
    CURR_FAILED=$(echo "$STATUS_OUTPUT" | grep "Currently failed" | sed -E 's/.*:\s*//' || true)
    TOTAL_FAILED=$(echo "$STATUS_OUTPUT" | grep "Total failed" | sed -E 's/.*:\s*//' || true)
    FILE_LIST=$(echo "$STATUS_OUTPUT" | grep -E "File list|Journal matches" | sed -E 's/.*:\s*//' || true)
    CURR_BANNED=$(echo "$STATUS_OUTPUT" | grep "Currently banned" | sed -E 's/.*:\s*//' || true)
    TOTAL_BANNED_JAIL=$(echo "$STATUS_OUTPUT" | grep "Total banned" | sed -E 's/.*:\s*//' || true)
    BANNED_IPS=$(echo "$STATUS_OUTPUT" | grep "Banned IP list" | sed -E 's/.*:\s*//' || true)
    
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
            cc=$(geo_cc "$ip")
            echo "      ${RED}- ${ip}${RESET} ${DIM}($cc)${RESET}"
        done
    else
        echo "  ${DIM}Banned IPs:${RESET}      ${GREEN}none${RESET}"
    fi
    
    echo "$HR"
done <<< "$JAILS"

echo "${BOLD}Summary:${RESET} ${JAIL_COUNT} jail(s) checked, ${BOLD}${TOTAL_BANNED}${RESET} IP(s) currently banned across all jails."
echo ""