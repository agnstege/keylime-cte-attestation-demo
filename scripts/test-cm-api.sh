#!/usr/bin/env bash
# Run on the VERIFIER. Exercises the exact CipherTrust Manager REST calls the
# broker makes: token, policy lookup, rule lookup, rule PATCH.
# Leaves rule #1 at deny,audit (the broker's fail-closed state).
set -euo pipefail

CM="${CM:-https://ciphertrust.home.arpa}"
CM_USER="${CM_USER:-broker-svc}"
POLICY="${POLICY:-cc-demo-policy}"
# -k: lab CM with a self-signed certificate. Drop it if CM's CA is trusted.
CURL=(curl -sSk --fail-with-body)

read -rsp "$CM_USER password: " CMPW; echo

body=$(python3 -c 'import json,sys; print(json.dumps({"grant_type":"password","username":sys.argv[1],"password":sys.argv[2]}))' "$CM_USER" "$CMPW")
JWT=$("${CURL[@]}" -X POST "$CM/api/v1/auth/tokens/" -H 'Content-Type: application/json' -d "$body" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["jwt"])')
AUTH="Authorization: Bearer $JWT"
echo "1/4 token: OK"

POL=$("${CURL[@]}" -H "$AUTH" "$CM/api/v1/transparent-encryption/policies?name=$POLICY" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["resources"][0]["id"])')
echo "2/4 policy $POLICY: $POL"

RULES=$("${CURL[@]}" -H "$AUTH" "$CM/api/v1/transparent-encryption/policies/$POL/securityrules")
echo "$RULES" | python3 -c 'import sys,json; [print("    rule", r.get("order_number"), r["id"], r.get("effect")) for r in json.load(sys.stdin)["resources"]]'
RULE=$(echo "$RULES" | python3 -c 'import sys,json; print(sorted(json.load(sys.stdin)["resources"], key=lambda r: r.get("order_number",0))[0]["id"])')
echo "3/4 gated rule: $RULE"

"${CURL[@]}" -X PATCH -H "$AUTH" -H 'Content-Type: application/json' \
  "$CM/api/v1/transparent-encryption/policies/$POL/securityrules/$RULE" -d '{"effect":"deny,audit"}' >/dev/null
echo "4/4 PATCH effect=deny,audit: OK"
