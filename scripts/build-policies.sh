#!/usr/bin/env bash
# Run on the VERIFIER as root.
# Captures the workload's boot event log and IMA log, hashes every file under
# /usr, /etc and /opt on the workload, and builds the Keylime measured-boot and
# runtime policies from them. Nothing is installed or left behind on the workload.
#
# Run it right after a clean reboot of the workload, before anything else runs.
# /root and /tmp are deliberately NOT hashed: the tamper demo runs from /root.
set -euo pipefail

WORKLOAD="${WORKLOAD:-workload.home.arpa}"
WORK="${WORK:-/root/wl}"
OUT="${OUT:-/root}"

command -v keylime-policy >/dev/null || {
  echo "keylime-policy not found (needs Keylime 7.12+). See docs/RUNBOOK.md for older tools." >&2
  exit 1
}

mkdir -p "$WORK"

echo "Capturing boot and IMA logs from $WORKLOAD"
# securityfs files report size 0, so stream them with cat rather than scp
ssh "root@$WORKLOAD" 'cat /sys/kernel/security/tpm0/binary_bios_measurements' > "$WORK/bios_measurements"
ssh "root@$WORKLOAD" 'cat /sys/kernel/security/ima/ascii_runtime_measurements' > "$WORK/ima_measurements"

echo "Hashing /usr /etc /opt on $WORKLOAD (this takes a minute)"
# sha256sum prefixes "\" to lines for file names containing backslashes;
# keylime-policy rejects those lines, and none of them are executables.
# shellcheck disable=SC1003  # '^\\' is a literal leading backslash, not a quote escape
ssh "root@$WORKLOAD" 'find /usr /etc /opt -xdev -type f -print0 | xargs -0 sha256sum 2>/dev/null; true' \
  | grep -v '^\\' > "$WORK/allowlist.txt"

for f in bios_measurements ima_measurements allowlist.txt; do
  [ -s "$WORK/$f" ] || { echo "Empty capture: $WORK/$f" >&2; exit 1; }
done
echo "Allowlist entries: $(wc -l < "$WORK/allowlist.txt")"

keylime-policy create measured-boot -e "$WORK/bios_measurements" -o "$OUT/mb.json"
keylime-policy create runtime \
  --ima-measurement-list "$WORK/ima_measurements" \
  --allowlist "$WORK/allowlist.txt" \
  -o "$OUT/runtime.json"

echo "Wrote $OUT/mb.json and $OUT/runtime.json"
echo "Next: keylime_tenant -c add (first time) or scripts/reset-demo.sh (after changes)"
