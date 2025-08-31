#!/usr/bin/env bash
set -euo pipefail
: "${CONF:=$HOME/.f2b-rapsheet.conf}"

# ---------------- defaults (overridden by config) ----------------
JAILS="apache-badbots recidive" # include custom jails, if any
MAX_LINES=5
ACCESS_LOG="/var/log/apache2/access.log" # adjust as needed, e.g. /var/log/nginx/access.log
IP_REGEX='^([0-9]{1,3}[.]){3}[0-9]{1,3}$|^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+$'  # IPv4/IPv6
# -----------------------------------------------------------------

TARGET_IP=""
AUTO_JAILS=false
OVERRIDE_JAILS=""

die(){ echo "Error: $*" >&2; exit 1; }
usage(){
  cat >&2 <<EOF
Usage: $(basename "$0") [-g IP] [-c CONFIG] [-j "j1 j2"] [--auto-jails]
  -g IP          Only show this IP
  -c CONFIG      Path to config file (default: ${CONF})
  -j "..."       Override jail list (space-separated)
  --auto-jails   Use 'fail2ban-client status --list' to detect jails
  -h, --help     Show this help
EOF
  exit 2
}

# parse CLI (so -c can take effect before sourcing config)
while [[ $# -gt 0 ]]; do
  case "$1" in
    -g) TARGET_IP="${2:-}"; shift 2 ;;
    -c) CONF="${2:-}"; shift 2 ;;
    -j) OVERRIDE_JAILS="${2:-}"; shift 2 ;;
    --auto-jails) AUTO_JAILS=true; shift ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

# source config if present
[[ -f "$CONF" ]] && source "$CONF"

# CLI override for jails wins
[[ -n "$OVERRIDE_JAILS" ]] && JAILS="$OVERRIDE_JAILS"

# auto-discover jails
if $AUTO_JAILS; then
  JAILS="$(sudo fail2ban-client status --list 2>/dev/null | tr -s ' ' '\n' | sed '/^$/d')"
fi

[[ -n "${ACCESS_LOG:-}" ]] || die "ACCESS_LOG not set (config or default)"
[[ -r "$ACCESS_LOG" ]]     || die "ACCESS_LOG not readable: $ACCESS_LOG"

get_banned() {
  local jail="$1"
  sudo fail2ban-client status "$jail" 2>/dev/null | awk '
    function is_ipv4(tok){ return (tok ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) }
    function is_ipv6(tok){ return (tok ~ /^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+$/ && tok !~ /:$/) }
    /Banned IP list/ {
      for (i=1; i<=NF; i++) {
        gsub(/[,;]/,"", $i)
        if (is_ipv4($i) || is_ipv6($i)) print $i
      }
    }
  '
}

# Collect banned IPs (unique, filtered)
all_banned="$(
  for j in $JAILS; do get_banned "$j"; done \
  | awk -v re="${IP_REGEX}" '$0 ~ re' \
  | sort -u
)"

# If targeting a specific IP, ensure it’s in the set
if [[ -n "$TARGET_IP" ]]; then
  grep -qxF "$TARGET_IP" <<<"$all_banned" \
    || die "Target IP $TARGET_IP is not currently banned in: $JAILS"
  all_banned="$TARGET_IP"
fi

ip_in_jail(){ sudo fail2ban-client status "$2" 2>/dev/null | grep -qw -- "$1"; }
ip_has_web_hits(){ grep -qE "^$1[[:space:]]" "$ACCESS_LOG"; }

print_hits() {
  local ip="$1"
  local file="$2"
  local lines="${3:-$MAX_LINES}"

  awk -v ip="$ip" '
    $1==ip {
      ts=$4" "$5; gsub(/\[|\]/,"",ts)
      method=$6; gsub(/"/,"",method)
      path=$7; status=$9
      ua=""
      if (match($0, /"[^"]*"$/)) { ua=substr($0,RSTART+1,RLENGTH-2) }
      printf("      [%-20s] %-6s %-40s -> %-3s | UA: %s\n",
             ts, method, path, status, ua)
    }' "$file" | tail -n "$lines"
}

for ip in $all_banned; do
  echo "=============================="
  echo "IP: $ip"
  echo "=============================="
  any=false
  for j in $JAILS; do
    if ip_in_jail "$ip" "$j"; then
      any=true
      echo "${j} hits:"
      # Special message for recidive with no web traffic
      if [[ "$j" == "recidive" ]] && ! ip_has_web_hits "$ip"; then
        echo "      (no web hits; likely SSH-only offender)"
        echo
        continue
      fi
      if [[ -n "$TARGET_IP" ]]; then
        # full dump for target
        awk -v ip="$ip" '
          $1==ip {
            ts=$4" "$5; gsub(/\[|\]/,"",ts)
            method=$6; gsub(/"/,"",method)
            path=$7; status=$9
            ua=""; if (match($0, /"[^"]*"$/)) { ua=substr($0,RSTART+1,RLENGTH-2) }
            printf("      [%s] %s %s -> %s | UA: %s\n", ts, method, path, status, ua)
          }' "$ACCESS_LOG" | sort | uniq
      else
        print_hits "$ip" "$ACCESS_LOG" "$MAX_LINES"
      fi
      echo
    fi
  done
  if [[ "$any" = false ]]; then
    echo "No web hits found in $ACCESS_LOG"
    echo
  fi
done
