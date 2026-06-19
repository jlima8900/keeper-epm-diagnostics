#!/usr/bin/env bash
#
# epm_endpoint_check.sh
#
# Read-only diagnostic for a Keeper Endpoint Privilege Manager (EPM) agent on a
# LINUX endpoint (Debian/Ubuntu). The Linux companion to epm_endpoint_check.ps1:
# it answers "is the agent healthy on this box, is it enrolled, and is it
# governing sudo?" and writes a redacted report you can attach to a support case.
#
# It NEVER changes anything and redacts secrets (registration tokens, keys).
#
# KEY FACT this tool exists to surface: once the EPM agent is installed, regular
# `sudo` is intercepted by a PAM hook and fails closed with
#   "ERROR: To run sudo, use keepersudo"
# Elevation must go through `keepersudo` / `keeperagent`. That is BY DESIGN, not a
# fault -- this tool tells you whether that state is in effect and why.
#
# Usage:
#   ./epm_endpoint_check.sh [--region eu|us|au|jp|ca|gov] [--out DIR] [--no-network]
#
# Output: a directory + .tar.gz next to it. Review before sharing.

set -uo pipefail
export PATH="/usr/local/sbin:/usr/sbin:/sbin:${PATH:-/usr/local/bin:/usr/bin:/bin}"

REGION="eu"; OUTBASE="."; DO_NET="yes"; TIMEOUT=6
while [ $# -gt 0 ]; do
  case "$1" in
    --region) REGION="${2:-eu}"; shift 2 ;;
    --out) OUTBASE="${2:-.}"; shift 2 ;;
    --no-network) DO_NET="no"; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -n 22; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
case "$REGION" in
  us) TLD="com" ;; eu) TLD="eu" ;; au) TLD="com.au" ;;
  jp) TLD="jp" ;; ca) TLD="ca" ;; gov|us_gov) TLD="us" ;;
  *) echo "Invalid --region '$REGION'" >&2; exit 2 ;;
esac
CLOUD="keepersecurity.${TLD}"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${OUTBASE%/}/epm-endpoint-diag-$(hostname 2>/dev/null || echo host)-${STAMP}"
mkdir -p "$OUT" || { echo "cannot create $OUT" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }
declare -a NOTES
note() { NOTES+=("$1"); printf '  %s\n' "$1"; }
cap() { local f="$1"; shift; { echo "\$ $*"; "$@"; } >>"$f" 2>&1 || echo "(command failed, continuing)" >>"$f"; }

# ---- redaction: registration tokens (REGION:uid:secret), keys, secrets -------
redact() {
  sed -E \
    -e 's/\b(EU|US|AU|JP|CA|GOV):[A-Za-z0-9_-]{16,}:[A-Za-z0-9_+/=-]{16,}/\1:[REDACTED_DEPLOYMENT_TOKEN]/g' \
    -e 's/(("?)([A-Za-z0-9_]*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|PASSPHRASE|_KEY|_SEED))("?)[[:space:]]*[:=][[:space:]]*"?)[^"[:space:]]+/\1[REDACTED]/Ig' \
    -e 's/([Bb]earer )[A-Za-z0-9._~+/=-]{8,}/\1[REDACTED]/g' \
    -e 's#-----BEGIN [A-Z ]*PRIVATE KEY-----#[REDACTED_PRIVATE_KEY]#g'
}

echo "Keeper EPM endpoint check (Linux)"
echo "Region=$REGION  Output=$OUT"
echo

# ---- host -----------------------------------------------------------------
echo "[*] Host"
{ echo "collected: $(date)"; echo "hostname: $(hostname 2>/dev/null)"; uname -a; } > "$OUT/host.txt"
[ -r /etc/os-release ] && cap "$OUT/host.txt" cat /etc/os-release
DISTRO_LIKE="$(. /etc/os-release 2>/dev/null; echo "${ID_LIKE:-${ID:-}}")"
case " $DISTRO_LIKE " in
  *debian*|*ubuntu*) : ;;
  *) note "NOTE: distro is not Debian/Ubuntu ($DISTRO_LIKE) -- the Keeper EPM Linux agent ships as .deb only; it likely is not installed here" ;;
esac

# ---- agent presence -------------------------------------------------------
echo "[*] EPM agent presence"
AF="$OUT/agent.txt"
PKG=""
if have dpkg-query; then PKG=$(dpkg-query -W -f='${Version}' keeper-privilege-manager 2>/dev/null); fi
if [ -n "$PKG" ]; then
  note "EPM agent installed: keeper-privilege-manager $PKG"
else
  note "WARN: keeper-privilege-manager package NOT installed (dpkg) -- agent absent or installed by other means"
fi
{ echo "package version: ${PKG:-<not via dpkg>}"
  echo "-- /opt/keeper layout --"; ls -la /opt/keeper /opt/keeper/bin /opt/keeper/sbin 2>/dev/null
  echo "-- elevation binaries (the EPM sudo path) --"; ls -la /usr/bin/keepersudo /usr/bin/keeperagent /opt/keeper/bin/sudo 2>/dev/null
} > "$AF" 2>&1
[ -x /usr/bin/keeperagent ] && note "keeperagent present (the elevation path: 'keeperagent <cmd>' instead of sudo)" \
  || note "NOTE: /usr/bin/keeperagent missing -- agent not installed or partial"

# ---- service --------------------------------------------------------------
echo "[*] Service"
SF="$OUT/service.txt"
if have systemctl; then
  ACT=$(systemctl is-active keeper-privilege-manager 2>/dev/null)
  ENB=$(systemctl is-enabled keeper-privilege-manager 2>/dev/null)
  note "service keeper-privilege-manager: active=${ACT:-unknown} enabled=${ENB:-unknown}"
  [ "$ACT" != "active" ] && [ -n "$PKG" ] && note "WARN: agent installed but service not active -- elevation/policy enforcement will not work"
  cap "$SF" systemctl status keeper-privilege-manager --no-pager
  { echo "-- recent journal (redacted) --"; journalctl -u keeper-privilege-manager -n 200 --no-pager 2>/dev/null; } | redact >> "$SF"
  # watchdog (keeps the agent alive)
  systemctl status keeper-watchdog --no-pager >/dev/null 2>&1 && cap "$SF" systemctl status keeper-watchdog --no-pager
else
  echo "(systemctl unavailable)" > "$SF"
fi

# ---- sudo interception (the headline) -------------------------------------
echo "[*] sudo interception"
PF="$OUT/sudo-pam.txt"
# The reliable signal that plain sudo is governed is: keepersudo present + agent
# active. The exact hook is NOT in /etc/pam.d/sudo (verified live) -- it's a sudo
# plugin / the agent's own mechanism -- so search broadly for the bundle, but
# DECIDE on keepersudo+service.
HOOK_FILES=$(grep -rilE 'keeper' /etc/pam.d/ /etc/sudo.conf /etc/sudoers /etc/sudoers.d/ 2>/dev/null)
{
  echo "Real sudo binary:"; ls -la /usr/bin/sudo 2>/dev/null; dpkg-divert --list 2>/dev/null | grep -i sudo
  echo "-- keeper references in sudo/PAM config (pam.d, sudo.conf, sudoers, sudoers.d) --"
  echo "${HOOK_FILES:-<none in the usual files>}"
  for f in $HOOK_FILES; do echo "== $f =="; grep -iE 'keeper' "$f" 2>/dev/null; done
  echo "-- /etc/sudo.conf (plugin wiring) --"; [ -r /etc/sudo.conf ] && grep -vE '^\s*#' /etc/sudo.conf 2>/dev/null
} > "$PF" 2>&1
if [ -e /usr/bin/keepersudo ] && [ "${ACT:-}" = "active" ]; then
  note "sudo is GOVERNED by EPM (keepersudo present + agent active) -- plain 'sudo' fails closed with 'ERROR: To run sudo, use keepersudo'. Elevate via keepersudo/keeperagent. Recovery: 'keeperagent dpkg --purge keeper-privilege-manager' (stopping the service alone does NOT restore sudo)."
  [ -z "$HOOK_FILES" ] && note "  (hook not in pam.d/sudoers -- implemented via a sudo plugin or the agent's own mechanism; see sudo-pam.txt)"
elif [ -e /usr/bin/keepersudo ]; then
  note "keepersudo present but service not active -- sudo governance may currently be off"
fi

# ---- enrollment / policies / plugins --------------------------------------
echo "[*] Enrollment & policies"
EF="$OUT/policies.txt"
{
  echo "-- plugins (capabilities the agent enforces) --"; ls -la /opt/keeper/sbin/Plugins 2>/dev/null
  echo "-- jobs --"; ls -1 /opt/keeper/sbin/Jobs 2>/dev/null
  echo "-- appsettings (redacted) --"; [ -r /opt/keeper/sbin/appsettings.json ] && redact < /opt/keeper/sbin/appsettings.json
  echo "-- local storage / state (existence only) --"; ls -la /opt/keeper/sbin/KeeperStorage 2>/dev/null
  echo "-- registration token on disk? (should NOT be left lying around) --"
  grep -rlE '\b(EU|US|AU|JP|CA|GOV):[A-Za-z0-9_-]{16,}:' /opt/keeper /etc/keeper 2>/dev/null | head
} | redact > "$EF" 2>&1
have keeperagent && cap "$OUT/agent.txt" /usr/bin/keeperagent --version

# ---- backend connectivity -------------------------------------------------
if [ "$DO_NET" = "yes" ]; then
  echo "[*] Backend reachability"
  NF="$OUT/network.txt"
  { echo "EPM agent talks to the Keeper cloud over TLS 443."
    echo "region=$REGION  endpoint=$CLOUD"; } > "$NF"
  if have getent; then echo "DNS $CLOUD -> $(getent ahosts "$CLOUD" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, -)" >> "$NF"; fi
  if have nc; then timeout "$TIMEOUT" nc -z -w "$TIMEOUT" "$CLOUD" 443 >/dev/null 2>&1; rc=$?; else timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$CLOUD/443" >/dev/null 2>&1; rc=$?; fi
  if [ "${rc:-1}" -eq 0 ]; then echo "TCP $CLOUD:443 OPEN" >> "$NF"; else echo "TCP $CLOUD:443 BLOCKED" >> "$NF"; note "WARN: $CLOUD:443 not reachable -- agent cannot reach the backend (no policy/approval sync)"; fi
  if have openssl; then echo | timeout "$TIMEOUT" openssl s_client -connect "$CLOUD:443" -servername "$CLOUD" 2>/dev/null | openssl x509 -noout -issuer -dates 2>/dev/null >> "$NF" || true; fi
fi

# ---- secret scan + package ------------------------------------------------
echo
echo "[*] Secret scan"
SCAN="$OUT/REDACTION-SCAN.txt"
grep -rinIE '(-----BEGIN [A-Z ]*PRIVATE KEY|(EU|US|AU|JP|CA|GOV):[A-Za-z0-9_-]{16,}:[A-Za-z0-9_+/=-]{16,}|(PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|_SEED)"?[ ]*[:=][ ]*"?[^ ",}]{6,})' "$OUT" 2>/dev/null \
  | grep -viE 'REDACTED' | grep -vF 'REDACTION-SCAN.txt' > "$SCAN" 2>/dev/null || true
RESID=$(grep -cE '.' "$SCAN" 2>/dev/null); RESID=${RESID:-0}
if [ "${RESID:-0}" -gt 0 ] 2>/dev/null; then
  note "WARN: secret-scan flagged ${RESID} line(s) that may be UNREDACTED -- review REDACTION-SCAN.txt before sharing"
else
  echo "no residual secret patterns detected ($(date))" > "$SCAN"; note "secret-scan: clean"
fi

echo
echo "[*] Packaging"
BUNDLE="${OUT}.tar.gz"
tar czf "$BUNDLE" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null \
  && echo "Bundle: $BUNDLE" || echo "tar failed; folder is at $OUT"
echo
echo "Summary"
[ "${#NOTES[@]}" -eq 0 ] && echo "  (no notable flags)"
echo
echo "Read-only. Secrets are redacted best-effort + scanned. Review before sharing."
echo "Reminder: on an EPM-managed Linux box, elevate with 'keepersudo'/'keeperagent', not 'sudo'."
