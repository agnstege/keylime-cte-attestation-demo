#!/usr/bin/env bash
# Run on the VERIFIER as root, after rolling the workload back to its
# clean-attested snapshot (or rebooting it) or after regenerating policies.
# Re-adds the agent with the current policies and waits for attestation.
# The re-add is always needed: once an agent fails, the verifier stops
# polling it until it is added again.
set -euo pipefail

WORKLOAD="${WORKLOAD:-workload.home.arpa}"
AGENT_UUID="${AGENT_UUID:-d432fbb3-d2f1-4a97-9ef7-75bd81c00000}"
POLICY_DIR="${POLICY_DIR:-/root}"
LOG="${LOG:-/root/wl/reset.log}"

mkdir -p "$(dirname "$LOG")"
echo "Re-adding agent $AGENT_UUID ($WORKLOAD) to the verifier"
if ! keylime_tenant -c update -t "$WORKLOAD" -u "$AGENT_UUID" \
     --runtime-policy "$POLICY_DIR/runtime.json" --mb-policy "$POLICY_DIR/mb.json" > "$LOG" 2>&1; then
  echo "keylime_tenant update failed; last lines of $LOG:" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

for _ in $(seq 1 30); do
  state=$(keylime_tenant -c cvstatus -u "$AGENT_UUID" 2>/dev/null \
    | grep -o '"operational_state": "[^"]*"' | head -1 | cut -d'"' -f4 || true)
  echo "verifier state: ${state:-unknown}"
  if [ "$state" = "Get Quote" ]; then
    echo "Attesting. The broker should log '>>> RELEASE keys' within about 2 seconds."
    exit 0
  fi
  sleep 2
done

echo "Agent did not reach 'Get Quote' within 60 s. Check: keylime_tenant -c cvstatus -u $AGENT_UUID" >&2
exit 1
