#!/usr/bin/env python3
"""
attestation-broker: gates CTE access on Keylime attestation state.

Keylime verifier says trusted  -> CTE security rule effect = permit,applykey
Anything else (pending/failed) -> CTE security rule effect = deny

Fail-closed: on startup, on any error reading the verifier, and on any
revocation webhook, the rule is forced to DENY.

Deps: requests (dnf install python3-requests). Everything else is stdlib.
Config: environment variables (see broker/broker.env.example).
"""
import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
import urllib3
from requests.adapters import HTTPAdapter

# ---------------------------------------------------------------- config
E = os.environ.get

CM_URL = E("CM_URL", "https://ciphertrust.home.arpa").rstrip("/")
CM_USER = E("CM_USER", "broker-svc")
CM_PASS = E("CM_PASS", "")
CM_VERIFY_TLS = E("CM_VERIFY_TLS", "false").lower() == "true"
CTE_POLICY_NAME = E("CTE_POLICY_NAME", "cc-demo-policy")
# Order number of the gated rule within the policy (1-based), so the broker
# can find it without hardcoding a rule UUID.
CTE_GATED_RULE_ORDER = int(E("CTE_GATED_RULE_ORDER", "1"))
EFFECT_ALLOW = E("EFFECT_ALLOW", "permit,audit,applykey")
EFFECT_DENY = E("EFFECT_DENY", "deny,audit")

KL_VERIFIER = E("KL_VERIFIER", "https://127.0.0.1:8881").rstrip("/")
KL_API = E("KL_API", "v2.3")  # check: curl ... /version (see docs/RUNBOOK.md)
KL_AGENT_UUID = E("KL_AGENT_UUID", "")
KL_CA = E("KL_CA", "/var/lib/keylime/cv_ca/cacert.crt")
KL_CERT = E("KL_CERT", "/var/lib/keylime/cv_ca/client-cert.crt")
KL_KEY = E("KL_KEY", "/var/lib/keylime/cv_ca/client-private.pem")
# Keylime's auto-generated verifier cert is issued to "server", not to an IP or
# hostname. Check the cert chains to the Keylime CA and is named this, whatever
# address we connect to (Keylime's own tenant skips the name check entirely).
KL_TLS_NAME = E("KL_TLS_NAME", "server")

POLL_SECONDS = float(E("POLL_SECONDS", "2"))
WEBHOOK_PORT = int(E("WEBHOOK_PORT", "8080"))

# Keylime verifier operational_state codes
TRUSTED = {3, 4}                 # Get Quote / Get Quote (retry)
FAILED = {7, 9, 10}              # Failed / Invalid Quote / Tenant Failed
STATE_NAMES = {
    0: "Registered", 1: "Start", 2: "Saved", 3: "Get Quote",
    4: "Get Quote (retry)", 5: "Provide V", 6: "Provide V (retry)",
    7: "Failed", 8: "Terminated", 9: "Invalid Quote", 10: "Tenant Failed",
}

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-5s %(message)s")
log = logging.getLogger("broker")
if not CM_VERIFY_TLS:
    urllib3.disable_warnings()


# ------------------------------------------------------------- CM client
class CM:
    """Minimal CipherTrust Manager REST client for one CTE policy rule.

    Endpoint paths match the CM v1 transparent-encryption API. Verify them
    against your CM's API playground (https://ciphertrust.home.arpa/playground_v2) before use.
    """

    def __init__(self):
        self.s = requests.Session()
        self.s.verify = CM_VERIFY_TLS
        self.token_exp = 0.0
        self.policy_id = None
        self.rule_id = None

    def _auth(self):
        if time.time() < self.token_exp - 30:
            return
        r = self.s.post(f"{CM_URL}/api/v1/auth/tokens/", json={
            "grant_type": "password", "username": CM_USER, "password": CM_PASS})
        r.raise_for_status()
        body = r.json()
        self.s.headers["Authorization"] = f"Bearer {body['jwt']}"
        self.token_exp = time.time() + int(body.get("duration", 300))

    def _req(self, method, path, **kw):
        self._auth()
        r = self.s.request(method, f"{CM_URL}/api/v1{path}", timeout=10, **kw)
        if r.status_code == 401:            # token expired early: retry once
            self.token_exp = 0
            self._auth()
            r = self.s.request(method, f"{CM_URL}/api/v1{path}", timeout=10, **kw)
        r.raise_for_status()
        return r.json() if r.content else {}

    def resolve(self):
        res = self._req("GET", "/transparent-encryption/policies",
                        params={"name": CTE_POLICY_NAME})
        pols = res.get("resources", [])
        if not pols:
            raise RuntimeError(f"CTE policy '{CTE_POLICY_NAME}' not found")
        self.policy_id = pols[0]["id"]
        rules = self._req(
            "GET", f"/transparent-encryption/policies/{self.policy_id}/securityrules"
        ).get("resources", [])
        rules.sort(key=lambda r: r.get("order_number", 0))
        if len(rules) < CTE_GATED_RULE_ORDER:
            raise RuntimeError("gated rule not found; check CTE_GATED_RULE_ORDER")
        rule = rules[CTE_GATED_RULE_ORDER - 1]
        self.rule_id = rule["id"]
        log.info("CM policy=%s gated rule=%s current effect=%s",
                 self.policy_id, self.rule_id, rule.get("effect"))
        return rule.get("effect")

    def set_effect(self, effect):
        self._req(
            "PATCH",
            f"/transparent-encryption/policies/{self.policy_id}"
            f"/securityrules/{self.rule_id}",
            json={"effect": effect})


# --------------------------------------------------------- Keylime client
class _ExpectName(HTTPAdapter):
    """Verify the server cert against a fixed name instead of the URL host."""

    def __init__(self, name, **kw):
        self._name = name
        super().__init__(**kw)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["assert_hostname"] = self._name
        return super().init_poolmanager(*args, **kwargs)


KL = requests.Session()
KL.mount("https://", _ExpectName(KL_TLS_NAME))


def keylime_state():
    """Return operational_state int, or None if unreachable/unknown."""
    url = f"{KL_VERIFIER}/{KL_API}/agents/{KL_AGENT_UUID}"
    try:
        # cert/verify per call: a REQUESTS_CA_BUNDLE env var would override Session.verify
        r = KL.get(url, cert=(KL_CERT, KL_KEY), verify=KL_CA, timeout=5)
        if r.status_code == 404:
            return None                      # agent not added to verifier
        r.raise_for_status()
        return int(r.json()["results"]["operational_state"])
    except Exception as e:                   # noqa: BLE001 - fail closed
        log.warning("verifier query failed: %s", e)
        return None


# ------------------------------------------------------------ gate logic
class Gate:
    def __init__(self, cm):
        self.cm = cm
        self.lock = threading.Lock()
        self.effect = None

    def enforce(self, want, reason):
        with self.lock:
            if want == self.effect:
                return
            try:
                self.cm.set_effect(want)
                self.effect = want
                tag = "RELEASE" if want == EFFECT_ALLOW else "WITHHOLD"
                log.info(">>> %s keys  (rule effect=%s)  reason: %s",
                         tag, want, reason)
            except Exception as e:           # noqa: BLE001
                log.error("CM update failed (%s); will retry", e)

    def poll_forever(self):
        last = object()
        while True:
            st = keylime_state()
            if st != last:
                log.info("verifier state: %s", STATE_NAMES.get(st, st))
                last = st
            if st in TRUSTED:
                self.enforce(EFFECT_ALLOW, "attestation passing")
            elif st in FAILED:
                self.enforce(EFFECT_DENY, f"attestation {STATE_NAMES[st]}")
            else:
                self.enforce(EFFECT_DENY, f"not attested ({STATE_NAMES.get(st, st)})")
            time.sleep(POLL_SECONDS)


def make_handler(gate):
    class Hook(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            try:
                payload = json.loads(body or b"{}")
            except ValueError:
                payload = {"raw": body[:200].decode(errors="replace")}
            log.warning("revocation webhook received: %s",
                        json.dumps(payload)[:300])
            gate.enforce(EFFECT_DENY, "revocation webhook")
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_):
            pass
    return Hook


def main():
    if not (CM_PASS and KL_AGENT_UUID):
        raise SystemExit("CM_PASS and KL_AGENT_UUID must be set")
    cm = CM()
    cm.resolve()
    gate = Gate(cm)
    gate.enforce(EFFECT_DENY, "broker start (fail closed)")
    srv = HTTPServer(("0.0.0.0", WEBHOOK_PORT), make_handler(gate))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log.info("webhook listening on :%d, polling every %ss",
             WEBHOOK_PORT, POLL_SECONDS)
    gate.poll_forever()


if __name__ == "__main__":
    main()
