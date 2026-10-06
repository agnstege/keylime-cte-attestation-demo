# Attestation flows: real hardware vs this lab

## Who triggers attestation

- **Real flow (Intel TDX on Azure or GCP):** the CTE agent starts it. Registering with Confidential Computing enabled and a client profile that names Intel Tiber Trust Services makes the agent send TDX evidence to CipherTrust Manager. CipherTrust Manager forwards it to Intel and releases or withholds keys based on the verdict.
- **This lab:** CipherTrust Manager and the CTE agent never know attestation exists. The Keylime verifier attests the VM every few seconds on its own. The broker turns that verdict into a CTE policy change, which CipherTrust Manager pushes to the agent as normal.

So the Intel portal, the Attestation Authority connections, the Confidential Computing section of the client profile, the CC prompt at install (answer N) and `cc_check` are all deliberately skipped.

## Real flow: Intel TDX and Intel Tiber Trust Services

```mermaid
sequenceDiagram
  autonumber
  actor Admin
  participant ITTS as Intel Tiber Trust Services
  participant Cloud as Azure or GCP
  participant CM as CipherTrust Manager
  participant Agent as CTE agent on TDX VM
  Note over Admin,Agent: One-off setup
  Admin->>ITTS: Create appraisal policy (TDX, optional MRTD) and API keys
  Admin->>Cloud: Provision TDX confidential VM with a cloud kernel
  Admin->>CM: Add Attestation Authority connections (admin + attestation)
  CM->>ITTS: Fetch appraisal policies over admin connection
  Admin->>CM: Client profile with Confidential Computing section, registration token
  Admin->>Agent: Install CTE, register with token, enable CC = Y
  Note over Admin,Agent: Runtime, started by the agent
  Agent->>Agent: Read TDX evidence from the vTPM
  Agent->>CM: Attestation request with evidence
  CM->>ITTS: Forward evidence over attestation connection
  ITTS->>ITTS: Verify quote chains to Intel, apply appraisal policy
  ITTS-->>CM: Result (pass, or fail e.g. TCB OutOfDate, MRTD mismatch)
  alt Pass
    CM-->>Agent: Keys released
    Agent->>Agent: GuardPoint data readable
  else Fail
    CM-->>Agent: Keys withheld, client status Warning
    Agent->>Agent: GuardPoint access blocked
  end
```

Vendor documentation says CipherTrust Manager contacts Intel "when a request is received from the agent". It doesn't say how often the agent re-attests after registration.

## This lab: Keylime and the broker on Proxmox

```mermaid
sequenceDiagram
  autonumber
  actor Admin
  participant KV as Keylime verifier
  participant KA as Keylime agent on workload
  participant B as Broker
  participant CM as CipherTrust Manager
  participant Agent as CTE agent on workload
  Note over Admin,Agent: One-off setup
  Admin->>KA: Proxmox VM with swtpm vTPM, Secure Boot, IMA
  Admin->>KV: Measured-boot and runtime policies from a clean boot
  Admin->>KV: Enrol agent (keylime_tenant add)
  Admin->>CM: Normal profile and token, cc-demo-policy rule 1 = deny
  Admin->>Agent: Install CTE-U, register with token, CC = N
  Admin->>B: Start broker (forces deny on start)
  Note over Admin,Agent: Runtime, driven by the verifier
  loop Every few seconds
    KV->>KA: Request TPM quote and IMA log
    KA-->>KV: Quote (PCRs) plus measurement list
    KV->>KV: Compare with measured-boot and runtime policies
    B->>KV: Poll agent state every 2 s
  end
  alt Attested
    B->>CM: PATCH rule 1 effect = permit,applykey
    CM-->>Agent: Push updated policy
    Agent->>Agent: GuardPoint data readable
  else Failed (tamper)
    KV->>B: Revocation webhook
    B->>CM: PATCH rule 1 effect = deny
    CM-->>Agent: Push updated policy
    Agent->>Agent: GuardPoint access blocked
  end
```

The enforcement point moves. In the real flow, CipherTrust Manager gates key release itself. In the lab, it releases keys as normal and the gate is the policy rule the broker toggles. The audience sees the same outcome; say this once when presenting.

## Step-by-step mapping

| Real flow | This lab | Status |
|---|---|---|
| Intel portal: appraisal policy (TDX, MRTD), attestation and admin API keys | Keylime measured-boot and runtime policies | Replaced |
| TDX confidential VM on Azure or GCP, cloud kernel | Proxmox VM: q35, OVMF, Secure Boot, swtpm vTPM, Rocky 9 with pinned kernel | Replaced |
| CipherTrust Manager Attestation Authority connections | None; the broker uses a service account on the normal REST API | Skipped |
| Client profile Confidential Computing section | Normal client profile | Skipped |
| Registration token bound to the CC profile | Normal registration token | Same, minus CC |
| CTE install, answer Y to Confidential Computing | CTE-U install, answer N | Same, minus CC |
| `cc_check` and MRTD checks | `keylime_tenant -c cvstatus` shows `Get Quote` | Replaced |
| Agent sends TDX evidence; CipherTrust Manager forwards it | Keylime verifier pulls the TPM quote and IMA log | Replaced |
| Intel verifies and applies policy | Keylime checks PCRs and IMA hashes against policies | Replaced |
| CipherTrust Manager releases or withholds keys | Broker sets rule 1 to `permit,applykey` or `deny` | Replaced |
| Standard CTE policies and GuardPoints | `cc-demo-policy`, GuardPoint `/data` | Same |
