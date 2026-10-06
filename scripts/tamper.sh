#!/usr/bin/env bash
# Run on the WORKLOAD as root, with:  bash tamper.sh
# (Run it via bash, not ./tamper.sh: executing this file directly would itself
#  be measured by IMA and trip attestation before the timer starts.)
#
# Drops and runs an unapproved binary in /root, then times how long until
# CTE denies access to the protected file.
set -u

SECRET="${SECRET:-/data/secret.txt}"
TIMEOUT="${TIMEOUT:-120}"

if ! cat "$SECRET" >/dev/null 2>&1; then
  echo "$SECRET is already denied. Reset the demo first (scripts/reset-demo.sh on the verifier)." >&2
  exit 1
fi
echo "Before: $(cat "$SECRET")"

printf '#!/bin/sh\necho "implant running"\n' > /root/implant.sh
chmod +x /root/implant.sh

start=$(date +%s.%N)
/root/implant.sh

while cat "$SECRET" >/dev/null 2>&1; do
  now=$(date +%s.%N)
  if awk -v a="$start" -v b="$now" -v t="$TIMEOUT" 'BEGIN{exit !(b-a>t)}'; then
    echo "Still readable after ${TIMEOUT}s. Check the verifier and broker logs." >&2
    exit 1
  fi
  sleep 0.5
done

end=$(date +%s.%N)
awk -v a="$start" -v b="$end" 'BEGIN{printf "Access denied %.1f s after the implant ran\n", b-a}'
