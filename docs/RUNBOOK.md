# Runbook: attestation-gated CTE on Proxmox

Build and demo guide for the lab described in the [README](../README.md). Keylime (TPM attestation) stands in for Intel TDX and Intel Tiber Trust Services; a broker flips a CTE security rule in CipherTrust Manager between `deny` and `permit,applykey` based on the attestation verdict.

**Fidelity note for the audience:** the vTPM is software (swtpm), so this proves the *workflow*, not a hardware root of trust. In the real confidential-computing flow CipherTrust Manager withholds keys itself until attestation passes; here the gate is a policy rule that CipherTrust Manager pushes to the agent. See [attestation-flows.md](attestation-flows.md) for the side-by-side comparison.

Tested with CipherTrust Manager 2.24, CTE-U, Rocky Linux 9 and the Keylime packages in Rocky's AppStream repo.

---

## 0. Topology and names

| VM | Hostname | OS | Spec | Runs |
|---|---|---|---|---|
| CipherTrust Manager | `ciphertrust.home.arpa` | CM appliance | as licensed | CipherTrust Manager |
| Verifier | `verifier.home.arpa` | Rocky 9 | 2 vCPU / 4 GB | keylime_verifier, keylime_registrar, keylime_tenant, broker |
| Workload | `workload.home.arpa` | Rocky 9 | 4 vCPU / 8 GB, q35, OVMF, vTPM 2.0, EFI disk | CTE-U agent, Keylime agent (Rust), IMA, GuardPoint `/data`; optional GPU passthrough |

Ports: verifier 8881, registrar 8890/8891, agent 9002, broker webhook 8080 (localhost only), CipherTrust Manager 443.

| Name | What it is |
|---|---|
| `ciphertrust.home.arpa`, `verifier.home.arpa`, `workload.home.arpa` | Lab hostnames under `home.arpa` (RFC 8375, reserved for home networks). Define them on your lab DNS server (for example as DNS rewrites in AdGuard Home or Pi-hole) and give the VMs DHCP reservations. |
| `cc-demo-key` | CTE encryption key in CipherTrust Manager |
| `cc-demo-policy` | CTE Standard policy; rule #1 is the gated rule |
| `broker-svc` | CipherTrust Manager service account used by the broker |
| `d432fbb3-d2f1-4a97-9ef7-75bd81c00000` | Keylime agent UUID for the workload (the Rust agent's default) |
| `/root/mb.json`, `/root/runtime.json` | Keylime measured-boot and runtime (IMA) policies, on the verifier |
| `clean-attested` | Proxmox snapshot of the workload used as the demo reset point |

Check from each VM: `getent hosts ciphertrust.home.arpa verifier.home.arpa workload.home.arpa`

Get the repo onto the verifier as `/root/kit` (it needs `broker/`, `config/` and `scripts/`). From the PC where you cloned or downloaded it:
```bash
scp -r keylime-cte-attestation-demo root@verifier.home.arpa:/root/kit
```
Or clone it on the verifier directly with `git clone` into `/root/kit`.

---

## 1. Workload VM

**Proxmox:** machine `q35`, BIOS `OVMF (UEFI)`, add an EFI disk (pre-enrolled keys), then Add → TPM State → **v2.0**. Put the main disk, EFI disk **and TPM state** on snapshot-capable storage (LVM-thin such as `local-lvm`, or ZFS). TPM state is always raw, so on `dir` storage the VM can't be snapshotted at all.

```bash
# Verify the TPM and boot event log
ls -l /dev/tpm0 /dev/tpmrm0
ls -l /sys/kernel/security/tpm0/binary_bios_measurements
dnf -y install tpm2-tools && tpm2_pcrread sha256:0,1,4,7
```

**Pin the kernel.** CTE-U runs in userspace, so it isn't tied to a kernel build. The pin is for Keylime: a kernel update changes the boot measurements and fails attestation mid-demo.
```bash
dnf -y install python3-dnf-plugin-versionlock
dnf versionlock add kernel kernel-core kernel-modules
```

**Secure Boot:** leave it on. CTE-U adds no kernel module, so there is no signing key to enrol; Secure Boot stays on to strengthen what measured boot proves.

**IMA (executables only).** The policy is in [`config/workload/ima-policy`](../config/workload/ima-policy); paste it:
```bash
mkdir -p /etc/ima
cat > /etc/ima/ima-policy <<'EOF'
# Executables only, so CTE GuardPoint reads on /data don't flood the log.
# Comments must be on their own lines: the kernel rejects the whole policy on any unknown token.
# proc, sysfs, debugfs, tmpfs, devpts, binfmt_misc, securityfs, selinuxfs, cgroup, cgroup2, nsfs
dont_measure fsmagic=0x9fa0
dont_measure fsmagic=0x62656572
dont_measure fsmagic=0x64626720
dont_measure fsmagic=0x01021994
dont_measure fsmagic=0x1cd1
dont_measure fsmagic=0x42494e4d
dont_measure fsmagic=0x73636673
dont_measure fsmagic=0xf97cff8c
dont_measure fsmagic=0x27e0eb
dont_measure fsmagic=0x63677270
dont_measure fsmagic=0x6e736673
measure func=BPRM_CHECK mask=MAY_EXEC
measure func=FILE_MMAP mask=MAY_EXEC
measure func=MODULE_CHECK
EOF
grubby --update-kernel=ALL --args="ima_hash=sha256 ima_template=ima-ng"
reboot
# after the reboot
cat /sys/kernel/security/ima/policy        # should list exactly the rules above
head /sys/kernel/security/ima/ascii_runtime_measurements
```
If the policy output doesn't match, `journalctl -b | grep -i ima` shows why it was rejected.

---

## 2. CTE-U and CipherTrust Manager

1. **Key:** create AES-256 key `cc-demo-key` (CTE-usable, XTS or CBC-CS1).
2. **Policy** `cc-demo-policy` (Standard):
   - Security rule **#1** (the gated rule): resource any, user any, process any, action `all_ops`, effect `permit,audit,applykey` (for seeding).
   - Key rule: `cc-demo-key`.
3. **Install CTE-U** on the workload and register it against `ciphertrust.home.arpa` with a registration token and profile as usual.
   - Answer **N** to confidential computing: there is no TDX here.
   - Answer **N** to hardware association: snapshot restores, clones and GPU passthrough change the hardware fingerprint and would lock the agent out, which looks exactly like an attestation failure.
   ```bash
   systemctl list-units --all | grep -i -E 'cte|secfs|vor|vmd'   # agent services running
   ```
   The client should show **Healthy** in CipherTrust Manager (Transparent Encryption → Clients).
4. **GuardPoint:** `/data` with `cc-demo-policy`.
5. **Seed data:**
   ```bash
   echo "TOP SECRET: Q4 merger target = ACME" > /data/secret.txt
   cat /data/secret.txt          # plaintext via CTE
   ```
6. **Set rule #1 to `deny,audit`** in the UI and confirm `cat /data/secret.txt` is denied.
7. **Broker service account:** CipherTrust Manager user `broker-svc`, member of the CTE Admins group (it needs to edit policies). Nothing more.
8. **Test the API calls the broker makes**, from the verifier:
   ```bash
   bash /root/kit/scripts/test-cm-api.sh
   ```
   The API playground lists paths relative to `/api`, so `/v1/...` there is `/api/v1/...` on the wire. If any call fails, adjust `broker.py` (`_auth()`, `resolve()`, `set_effect()`) to match your version.
9. **Measure push latency:** flip the rule by hand and time how long until `cat` on the workload changes behaviour. If it's more than about 10 seconds, check the client's communication settings.

---

## 3. Keylime

### Verifier VM
```bash
dnf -y install keylime        # verifier, registrar, tenant, keylime-policy
mkdir -p /etc/keylime/{verifier,registrar,tenant}.conf.d
cp /root/kit/config/verifier/verifier.conf.d-10-lab.conf            /etc/keylime/verifier.conf.d/10-lab.conf
cp /root/kit/config/verifier/verifier.conf.d-50-broker-webhook.conf /etc/keylime/verifier.conf.d/50-broker-webhook.conf
cp /root/kit/config/verifier/registrar.conf.d-10-lab.conf           /etc/keylime/registrar.conf.d/10-lab.conf
cp /root/kit/config/verifier/tenant.conf.d-10-lab.conf              /etc/keylime/tenant.conf.d/10-lab.conf
systemctl enable --now keylime_verifier keylime_registrar
ss -tlnp | grep -E ':(8881|8890|8891)'   # expect 0.0.0.0, not 127.0.0.1
firewall-cmd --permanent --add-port={8881,8890,8891}/tcp && firewall-cmd --reload
```
What the snippets do:
- **`ip = 0.0.0.0`** for the verifier and registrar. The default is `127.0.0.1`, which makes the agent's registration fail and the tenant's `add` return 404.
- **Revocation webhook** to `http://127.0.0.1:8080/revocation`, so the broker hears about failures immediately.
- **`require_ek_cert = False`**, because swtpm has no manufacturer EK certificate. Lab only; the tenant will warn `DANGER: EK cert checking is disabled` on every `add`.

### Workload VM
```bash
dnf -y install keylime-agent-rust
mkdir -p /etc/keylime/agent.conf.d
cat > /etc/keylime/agent.conf.d/10-lab.conf <<'EOF'
[agent]
uuid = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
ip = "0.0.0.0"
contact_ip = "workload.home.arpa"
registrar_ip = "verifier.home.arpa"
EOF
firewall-cmd --permanent --add-port=9002/tcp && firewall-cmd --reload
```
If the agent rejects hostnames for `contact_ip`/`registrar_ip`, use the DHCP-reserved IPs.

Copy the verifier's CA to the workload (the agent uses it to trust the verifier). The package creates the `keylime` user, so do this after installing it. From the verifier:
```bash
ssh root@workload.home.arpa 'id keylime && install -d -m 700 -o keylime -g keylime /var/lib/keylime/cv_ca'
scp /var/lib/keylime/cv_ca/cacert.crt root@workload.home.arpa:/var/lib/keylime/cv_ca/cacert.crt
ssh root@workload.home.arpa 'chown keylime:keylime /var/lib/keylime/cv_ca/cacert.crt && systemctl enable --now keylime_agent && systemctl restart keylime_agent'
keylime_tenant -c reglist        # the agent UUID should be listed
```

### Policies (from a known-good boot)
The policy tools ship with the full Keylime package on the verifier. Don't install anything extra on the workload: every new binary there changes the measurements you're about to capture.

Reboot the workload (clean state, nothing extra run), then on the verifier:
```bash
bash /root/kit/scripts/build-policies.sh
```
The script:
1. streams the boot event log and IMA log from the workload;
2. hashes every file under `/usr`, `/etc` and `/opt` on the workload, so legitimate binaries that haven't run yet (SSH sessions, CTE-U helpers, `journalctl`) don't fail attestation;
3. builds `/root/mb.json` and `/root/runtime.json` with `keylime-policy`.

`/root` and `/tmp` are deliberately not hashed. The tamper demo runs its implant from `/root`, which must fail. Don't run it from `/tmp`: the IMA policy excludes tmpfs, so it would never be measured.

Regenerate the policies after any `dnf` update or package install on the workload, then run `scripts/reset-demo.sh`.

### Enrol
```bash
keylime_tenant -c add -t workload.home.arpa -u d432fbb3-d2f1-4a97-9ef7-75bd81c00000 \
  --runtime-policy /root/runtime.json --mb-policy /root/mb.json
keylime_tenant -c cvstatus -u d432fbb3-d2f1-4a97-9ef7-75bd81c00000
```
Expect `"operational_state": "Get Quote"` and a rising `attestation_count`. If it's `Invalid Quote`, `last_event_id` names the failing check (see Troubleshooting).

---

## 4. Broker (on the verifier)

The broker runs on the verifier, not the workload:
- it needs Keylime's client certificates in `/var/lib/keylime/cv_ca/`, which exist only on the verifier;
- the revocation webhook points at `127.0.0.1:8080` on the verifier;
- the machine being attested must not control its own gate.

```bash
dnf -y install python3-requests
install -d /opt/attestation-broker
install -m 755 /root/kit/broker/broker.py /opt/attestation-broker/broker.py
install -m 600 /root/kit/broker/broker.env.example /etc/attestation-broker.env
vi /etc/attestation-broker.env          # set CM_PASS, and anything else that differs in your lab
```
Find the verifier's API version for `KL_API`. The verifier's auto-generated certificate is issued to the name `server`, so `--resolve` maps that name to localhost:
```bash
curl -sS --resolve server:8881:127.0.0.1 --cacert /var/lib/keylime/cv_ca/cacert.crt \
  --cert /var/lib/keylime/cv_ca/client-cert.crt --key /var/lib/keylime/cv_ca/client-private.pem \
  https://server:8881/version
```
Set `KL_API=v<current_version>` from the reply and leave `KL_TLS_NAME=server`. Then:
```bash
install -m 644 /root/kit/broker/attestation-broker.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now attestation-broker
journalctl -fu attestation-broker
```
Expected log sequence: `WITHHOLD ... broker start (fail closed)`, then `verifier state: Get Quote`, then `>>> RELEASE keys`.

Now take the Proxmox snapshot `clean-attested` of the workload. That is the reset point for every demo run.

---

## 5. Demo script (about 8 minutes)

Screens:
- **A:** workload shell.
- **B:** `journalctl -fu attestation-broker` on the verifier.
- **C:** CipherTrust Manager UI, `cc-demo-policy` rule #1.
- **D:** optional, the CipherTrust Manager audit log.

1. **Untrusted at boot.** Stop the broker, reboot the workload, start the broker. `cat /data/secret.txt` is denied. B shows `WITHHOLD ... broker start (fail closed)`.
2. **Attest.** The verifier reaches `Get Quote`. B shows `>>> RELEASE keys`, C shows the effect flip to permit, and in A `cat` returns the plaintext.
3. **Tamper.** From the verifier, stream [`scripts/tamper.sh`](../scripts/tamper.sh) into a shell on the workload:
   ```bash
   ssh root@workload.home.arpa 'bash -s' < /root/kit/scripts/tamper.sh
   ```
   Nothing is copied to the workload, so it survives every snapshot rollback, and IMA never measures the script itself (bash reads it from stdin rather than executing a file).
   IMA measures the unknown `/root/implant.sh`, the verifier reports `Invalid Quote` and sends the webhook, and B shows `>>> WITHHOLD keys`. The script prints how many seconds it took for access to disappear.
4. **Data at rest is ciphertext** (optional): read the raw file from the Proxmox host or a non-CTE boot.
5. **Recover**, either way:
   - *Approve the change:* add the implant's hash to `/root/runtime.json`, then `bash /root/kit/scripts/reset-demo.sh`.
   - *Clean slate:* roll back to `clean-attested`, start the VM, then `bash /root/kit/scripts/reset-demo.sh`.

   The reset script is always needed: once an agent fails, the verifier stops polling it until it's re-added.

**Narrative map to the real flow:**

| Real confidential-computing flow | This lab |
|---|---|
| Agent registers | Agent registers |
| TDX quote | TPM quote and IMA log |
| Intel Tiber Trust Services decides | Keylime decides |
| CipherTrust Manager releases or withholds keys | Broker flips the CipherTrust Manager rule |

---

## 6. Optional: confidential-AI angle (GPU passthrough)

Pass a consumer GPU through to the workload (IOMMU on, `hostpci0`, NVIDIA driver). Point a local model or inference job at input in `/data`: when attestation passes the job runs, and after the tamper step it fails to read its input.

Notes:
- **The GPU isn't part of the trust chain.** Consumer GPUs have no confidential-computing mode, so it's the workload, not a trusted component.
- **Driver modules need signing.** NVIDIA kernel modules must be signed for Secure Boot.
- **Measurements change.** Regenerate both policies after installing the driver.

---

## 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `keylime_tenant -c add` returns 404 "Agent ... not found" | The agent never registered. Usually the registrar is bound to `127.0.0.1`: check `ss -tlnp`. Then `journalctl -u keylime_agent` on the workload. |
| `Invalid Quote`, `last_event_id: ima.validation.ima-ng.not_in_allowlist` | Something ran that isn't in the runtime policy. `journalctl -u keylime_verifier \| grep -i allowlist` names the file. Rerun `build-policies.sh` and `reset-demo.sh`. |
| `Invalid Quote`, `measured_boot...` or a PCR in `last_event_id` | Boot changed (kernel, driver, firmware). Regenerate policies from a fresh boot. |
| `keylime-policy` rejects a line starting with `\` | `sha256sum` escapes file names containing backslashes. `build-policies.sh` already filters these. |
| Broker logs `verifier query failed` with an SSL hostname error | `KL_TLS_NAME` must match the verifier certificate's name (`server` for Keylime's auto-generated cert). |
| Broker crash-loops with 401 on `/api/v1/auth/tokens/` | Wrong `CM_USER`/`CM_PASS` in `/etc/attestation-broker.env`. |
| Broker logs 404 from CipherTrust Manager | API path or policy name differs: run `scripts/test-cm-api.sh`. |
| Rule flips in CipherTrust Manager but access is unchanged | The agent isn't receiving policy pushes: check client status and communication settings. |
| `scp ... /var/lib/keylime/cv_ca/` fails with "dest open" | The directory doesn't exist on the workload yet. Use the `install -d` step in section 3. |
| Proxmox: "current guest configuration does not support taking new snapshots" | A disk (usually the TPM state) is on non-snapshot storage. With the VM stopped: `qm disk move $(qm list | awk '/workload/ {print $1}') tpmstate0 local-lvm --delete 1`. |
| IMA log huge | The policy wasn't loaded: `cat /sys/kernel/security/ima/policy`. |
