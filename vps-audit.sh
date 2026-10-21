#!/usr/bin/env bash
# vps-audit - read-only security and basics check for a Linux VPS.
# Maintained by Pro Gineous (https://progineous.com). MIT licensed.
set -euo pipefail

VERSION="1.0.1"
JSON=0
COLOR=1
DISK_TEST=0
DISK_TEST_MB=64

# Remove the disk test file even if the run is interrupted.
TMP_FILE=""
cleanup() { [[ -n "$TMP_FILE" ]] && rm -f "$TMP_FILE"; return 0; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
  cat <<USAGE
vps-audit $VERSION
Read-only security and basics audit for a Linux VPS. Prints a score out of 100
and the exact command to fix each finding. Changes nothing on the system.

Usage: vps-audit.sh [options]

Options:
  --json            Print results as JSON
  --no-color        Plain output (also honoured: NO_COLOR env variable)
  --disk-test       Run a larger 512MB write speed test (default test is 64MB)
  -h, --help        Show this help
  -V, --version     Show version

Run as root (sudo) for full results. Without root some checks are skipped.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json) JSON=1 ;;
    --no-color) COLOR=0 ;;
    --disk-test) DISK_TEST=1; DISK_TEST_MB=512 ;;
    -h|--help) usage; exit 0 ;;
    -V|--version) echo "vps-audit $VERSION"; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

[[ -n "${NO_COLOR:-}" || ! -t 1 ]] && COLOR=0
[[ $JSON -eq 1 ]] && COLOR=0

if [[ $COLOR -eq 1 ]]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; D=$'\e[2m'; C=$'\e[36m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; B=""; D=""; C=""; N=""
fi

have() { command -v "$1" >/dev/null 2>&1; }
IS_ROOT=0; [[ $(id -u) -eq 0 ]] && IS_ROOT=1

SCORE=0
MAX=0
RESULTS=()   # status|name|weight|detail|fix

# add STATUS NAME WEIGHT DETAIL FIX ; STATUS is pass, warn, fail or skip
add() {
  local status=$1 name=$2 weight=$3 detail=$4 fix=${5:-}
  case "$status" in
    pass) SCORE=$((SCORE + weight)); MAX=$((MAX + weight)) ;;
    warn) SCORE=$((SCORE + weight / 2)); MAX=$((MAX + weight)) ;;
    fail) MAX=$((MAX + weight)) ;;
    skip) ;;
  esac
  RESULTS+=("$status|$name|$weight|$detail|$fix")
}

# sshd effective setting, falls back to parsing config files
sshd_value() {
  local key=$1 val=""
  if have sshd && [[ $IS_ROOT -eq 1 ]]; then
    val=$(sshd -T 2>/dev/null | awk -v k="$key" 'tolower($1)==k {print $2; exit}') || true
  fi
  if [[ -z "$val" ]]; then
    local files=(/etc/ssh/sshd_config)
    if [[ -d /etc/ssh/sshd_config.d ]]; then
      for f in /etc/ssh/sshd_config.d/*.conf; do [[ -r "$f" ]] && files=("$f" "${files[@]}"); done
    fi
    for f in "${files[@]}"; do
      [[ -r "$f" ]] || continue
      val=$(awk -v k="$key" 'tolower($1)==k {print tolower($2); exit}' "$f") || true
      [[ -n "$val" ]] && break
    done
  fi
  printf '%s' "$val"
}

check_ssh() {
  if [[ ! -e /etc/ssh/sshd_config ]] && ! have sshd; then
    add skip "SSH server" 0 "OpenSSH server not installed"
    return
  fi
  local pa prl
  pa=$(sshd_value passwordauthentication)
  prl=$(sshd_value permitrootlogin)
  [[ -z "$pa" ]] && pa="yes (default)"
  [[ -z "$prl" ]] && prl="prohibit-password (default)"
  if [[ "$pa" == no ]]; then
    add pass "SSH password login" 15 "PasswordAuthentication no"
  else
    add fail "SSH password login" 15 "PasswordAuthentication $pa, bots can brute force passwords" \
      "echo 'PasswordAuthentication no' | sudo tee /etc/ssh/sshd_config.d/10-no-password.conf && sudo systemctl reload ssh  # add your SSH key first"
  fi
  case "$prl" in
    no) add pass "SSH root login" 10 "PermitRootLogin no" ;;
    prohibit-password*|without-password) add warn "SSH root login" 10 "PermitRootLogin $prl (key only)" \
      "echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-no-root.conf && sudo systemctl reload ssh  # use a sudo user first" ;;
    *) add fail "SSH root login" 10 "PermitRootLogin $prl" \
      "echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-no-root.conf && sudo systemctl reload ssh  # use a sudo user first" ;;
  esac
}

PORTS_DETAIL=""
check_ports() {
  if ! have ss; then
    add skip "Open ports" 0 "ss not found (install iproute2)"
    return
  fi
  local lines public=0 list=""
  lines=$(ss -H -tulnp 2>/dev/null || ss -H -tuln 2>/dev/null || true)
  while read -r proto _ _ _ local_addr _ rest; do
    [[ -z "${proto:-}" ]] && continue
    local addr port procname
    port=${local_addr##*:}
    addr=${local_addr%:*}
    case "$addr" in 127.*|"[::1]"|::1|"[::ffff:127."*) continue ;; esac
    procname=$(sed -n 's/.*users:(("\([^"]*\)".*/\1/p' <<<"${rest:-}")
    [[ -z "$procname" ]] && procname="?"
    public=$((public + 1))
    list+="$proto/$port($procname) "
  done <<<"$lines"
  PORTS_DETAIL=$(tr ' ' '\n' <<<"$list" | sed '/^$/d' | sort -u | paste -sd' ' -)
  local note=""
  [[ $IS_ROOT -eq 0 ]] && note=" (run as root to see all process names)"
  if [[ $public -eq 0 ]]; then
    add pass "Open ports" 10 "nothing listening on public interfaces"
  elif [[ $(wc -w <<<"$PORTS_DETAIL") -le 3 ]]; then
    add pass "Open ports" 10 "listening: $PORTS_DETAIL$note"
  else
    add warn "Open ports" 10 "listening: $PORTS_DETAIL$note" \
      "sudo ss -tulnp  # review each service, stop or bind to 127.0.0.1 what you do not need"
  fi
}

check_firewall() {
  local state="" 
  if have ufw && [[ $IS_ROOT -eq 1 ]]; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then state="ufw active"; fi
  fi
  if [[ -z "$state" ]] && have nft && [[ $IS_ROOT -eq 1 ]]; then
    if nft list ruleset 2>/dev/null | grep -Eq 'hook input.*policy drop|^\s*(drop|reject)'; then state="nftables rules with drop policy"; fi
  fi
  if [[ -z "$state" ]] && have iptables && [[ $IS_ROOT -eq 1 ]]; then
    if iptables -S INPUT 2>/dev/null | grep -Eq '^-P INPUT (DROP|REJECT)|-j (DROP|REJECT)'; then state="iptables INPUT filtering"; fi
  fi
  if [[ $IS_ROOT -eq 0 ]]; then
    add skip "Firewall" 0 "needs root to read firewall rules"
  elif [[ -n "$state" ]]; then
    add pass "Firewall" 15 "$state"
  else
    add fail "Firewall" 15 "no active firewall found (checked ufw, nftables, iptables)" \
      "sudo apt install ufw && sudo ufw allow OpenSSH && sudo ufw enable"
  fi
}

check_updates() {
  if have apt-get; then
    local n
    n=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst .*[Ss]ecurity' || true)
    if [[ "$n" -eq 0 ]]; then
      add pass "Security updates" 10 "no pending security updates (based on last apt update)"
    else
      add fail "Security updates" 10 "$n security updates pending" "sudo apt update && sudo apt upgrade"
    fi
  elif have dnf; then
    if dnf -q updateinfo list --security 2>/dev/null | grep -q .; then
      add fail "Security updates" 10 "security updates pending" "sudo dnf upgrade --security"
    else
      add pass "Security updates" 10 "no pending security updates"
    fi
  else
    add skip "Security updates" 0 "no apt-get or dnf found"
  fi
}

check_auto_updates() {
  if have apt-get; then
    if dpkg -s unattended-upgrades >/dev/null 2>&1 && grep -Rqs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/; then
      add pass "Automatic updates" 5 "unattended-upgrades installed and enabled"
    else
      add fail "Automatic updates" 5 "unattended-upgrades not installed or not enabled" \
        "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"
    fi
  elif have dnf; then
    if systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 || systemctl is-enabled dnf-automatic-install.timer >/dev/null 2>&1; then
      add pass "Automatic updates" 5 "dnf-automatic timer enabled"
    else
      add fail "Automatic updates" 5 "dnf-automatic not enabled" "sudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic.timer"
    fi
  else
    add skip "Automatic updates" 0 "unknown package manager"
  fi
}

check_fail2ban() {
  if have fail2ban-client || [[ -x /usr/bin/fail2ban-server ]]; then
    if have systemctl && systemctl is-active fail2ban >/dev/null 2>&1; then
      add pass "fail2ban" 5 "installed and running"
    else
      add warn "fail2ban" 5 "installed but not running" "sudo systemctl enable --now fail2ban"
    fi
  else
    add fail "fail2ban" 5 "not installed" "sudo apt install fail2ban && sudo systemctl enable --now fail2ban"
  fi
}

check_swap() {
  local swap_kb mem_kb
  swap_kb=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)
  mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
  if [[ "$swap_kb" -gt 0 ]]; then
    add pass "Swap" 5 "$((swap_kb / 1024)) MB swap, $((mem_kb / 1024)) MB RAM"
  elif [[ "$mem_kb" -lt 4194304 ]]; then
    add warn "Swap" 5 "no swap with only $((mem_kb / 1024)) MB RAM, the OOM killer will hit sooner" \
      "sudo fallocate -l 1G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile && echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab"
  else
    add pass "Swap" 5 "no swap, but $((mem_kb / 1024)) MB RAM"
  fi
}

check_disk() {
  local use avail
  read -r use avail < <(df -P / | awk 'NR==2 {gsub("%","",$5); print $5, $4}')
  if [[ "$use" -lt 80 ]]; then
    add pass "Disk space" 10 "/ is ${use}% used, $((avail / 1024)) MB free"
  elif [[ "$use" -lt 90 ]]; then
    add warn "Disk space" 10 "/ is ${use}% used, $((avail / 1024)) MB free" "sudo du -xh / --max-depth=2 2>/dev/null | sort -h | tail -20"
  else
    add fail "Disk space" 10 "/ is ${use}% used, $((avail / 1024)) MB free" "sudo du -xh / --max-depth=2 2>/dev/null | sort -h | tail -20"
  fi
}

DISK_SPEED=""
check_disk_speed() {
  if ! have dd; then add skip "Disk write speed" 0 "dd not found"; return; fi
  local dir tmp out
  dir=${TMPDIR:-/var/tmp}
  [[ -w "$dir" ]] || dir=/tmp
  local avail_kb
  avail_kb=$(df -Pk "$dir" | awk 'NR==2 {print $4}')
  if [[ "$avail_kb" -lt $(( (DISK_TEST_MB + 200) * 1024 )) ]]; then
    add skip "Disk write speed" 0 "not enough free space in $dir for a ${DISK_TEST_MB}MB test"
    return
  fi
  tmp=$(mktemp "$dir/vps-audit.XXXXXX")
  TMP_FILE=$tmp
  out=$(LC_ALL=C dd if=/dev/zero of="$tmp" bs=1M count="$DISK_TEST_MB" oflag=direct conv=fdatasync 2>&1 \
     || LC_ALL=C dd if=/dev/zero of="$tmp" bs=1M count="$DISK_TEST_MB" conv=fdatasync 2>&1) || true
  rm -f "$tmp"
  TMP_FILE=""
  DISK_SPEED=$(awk -F', ' '/copied/ {print $NF}' <<<"$out")
  if [[ -z "$DISK_SPEED" ]]; then
    add skip "Disk write speed" 0 "dd test failed"
    return
  fi
  local num unit mbs
  num=${DISK_SPEED% *}; unit=${DISK_SPEED#* }
  case "$unit" in
    GB/s) mbs=$(awk -v n="$num" 'BEGIN {printf "%d", n*1000}') ;;
    MB/s) mbs=$(awk -v n="$num" 'BEGIN {printf "%d", n}') ;;
    kB/s) mbs=0 ;;
    *) mbs=0 ;;
  esac
  if [[ "$mbs" -ge 100 ]]; then
    add pass "Disk write speed" 5 "$DISK_SPEED (${DISK_TEST_MB}MB direct write$([[ $DISK_TEST -eq 1 ]] && echo ", --disk-test"))"
  else
    add warn "Disk write speed" 5 "$DISK_SPEED (${DISK_TEST_MB}MB direct write), slow for a server" \
      "# slow disk or noisy neighbour; consider an NVMe VPS plan"
  fi
}

check_time() {
  if have timedatectl; then
    local synced
    synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
    if [[ "$synced" == yes ]]; then
      add pass "Time sync" 5 "clock synchronised (NTP)"
    elif [[ -z "$synced" ]]; then
      add skip "Time sync" 0 "timedatectl could not report (container or no systemd)"
    else
      add fail "Time sync" 5 "clock not synchronised" "sudo timedatectl set-ntp true"
    fi
  elif have chronyc && chronyc tracking >/dev/null 2>&1; then
    add pass "Time sync" 5 "chrony running"
  else
    add skip "Time sync" 0 "no timedatectl or chronyc"
  fi
}

check_reboot() {
  if [[ -f /var/run/reboot-required ]]; then
    local pk=""
    [[ -r /var/run/reboot-required.pkgs ]] && pk=" ($(sort -u /var/run/reboot-required.pkgs | tr '\n' ' ' | sed 's/ $//'))"
    add warn "Reboot required" 5 "a reboot is pending$pk" "sudo reboot  # pick a quiet moment"
  elif have needs-restarting && ! needs-restarting -r >/dev/null 2>&1; then
    add warn "Reboot required" 5 "a reboot is pending" "sudo reboot  # pick a quiet moment"
  else
    add pass "Reboot required" 5 "no reboot pending"
  fi
}

check_ssh; check_ports; check_firewall; check_updates; check_auto_updates
check_fail2ban; check_swap; check_disk; check_disk_speed; check_time; check_reboot

FINAL=0
[[ $MAX -gt 0 ]] && FINAL=$(( SCORE * 100 / MAX ))

json_esc() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\t'/ }; printf '%s' "$s"; }

if [[ $JSON -eq 1 ]]; then
  printf '{"tool":"vps-audit","version":"%s","host":"%s","root":%s,"score":%d,"checks":[' \
    "$VERSION" "$(json_esc "$(hostname)")" "$([[ $IS_ROOT -eq 1 ]] && echo true || echo false)" "$FINAL"
  first=1
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r st nm wt dt fx <<<"$r"
    [[ $first -eq 0 ]] && printf ','
    first=0
    printf '{"name":"%s","status":"%s","weight":%d,"detail":"%s","fix":"%s"}' \
      "$(json_esc "$nm")" "$st" "$wt" "$(json_esc "$dt")" "$(json_esc "$fx")"
  done
  printf ']}\n'
  exit 0
fi

# shellcheck disable=SC1091
os=$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}") || os=unknown
printf '\n%svps-audit %s%s  %s%s | %s | %s%s\n\n' "$B" "$VERSION" "$N" "$D" "$(hostname)" "$os" "$(uname -r)" "$N"
[[ $IS_ROOT -eq 0 ]] && printf '%sNot running as root: some checks are skipped. Use sudo for a full audit.%s\n\n' "$Y" "$N"

for r in "${RESULTS[@]}"; do
  IFS='|' read -r st nm _ dt fx <<<"$r"
  case "$st" in
    pass) tag="${G}[ PASS ]${N}" ;;
    warn) tag="${Y}[ WARN ]${N}" ;;
    fail) tag="${R}[ FAIL ]${N}" ;;
    skip) tag="${D}[ SKIP ]${N}" ;;
  esac
  printf '%s %-20s %s\n' "$tag" "$nm" "$dt"
  if [[ -n "$fx" && "$st" != pass ]]; then
    printf '         %sfix:%s %s%s%s\n' "$D" "$N" "$C" "$fx" "$N"
  fi
done

if [[ $FINAL -ge 80 ]]; then sc=$G; elif [[ $FINAL -ge 50 ]]; then sc=$Y; else sc=$R; fi
printf '\n%sScore: %s%d/100%s\n' "$B" "$sc" "$FINAL" "$N"
printf '%sScored on checks that could run. Read-only: nothing was changed.%s\n\n' "$D" "$N"
