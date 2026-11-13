---
name: attack-coverage-mapping
description: Map engagement activity to MITRE ATT&CK tactics and techniques — build a coverage layer (attempted/succeeded/blocked per technique), sequence adversary-emulation kill-chains, and produce detection-gap analysis for purple-team validation.
metadata:
  subdomain: adversary-emulation
  when_to_use: "mitre att&ck attack framework technique tactic ttp coverage navigator layer matrix adversary emulation threat profile kill chain detection gap purple team mapping"
  mitre_attack: T1190, T1059, T1133
---

# MITRE ATT&CK Coverage & Emulation Playbook

This skill translates the engagement into ATT&CK's language and back:
every observed or planned action is tagged with its technique ID
(`Txxxx` / `Txxxx.yyy`) and tactic (`TAxxxx`), and the result is a
coverage layer suitable for an ATT&CK-Navigator-style summary.

## 1. Coverage layer model

For each technique, track a status with evidence:

| Status | Meaning |
|---|---|
| `attempted` | executed, outcome pending/partial |
| `succeeded` | technique worked (evidence attached) |
| `blocked` | attempted, prevented (record the control) |
| `n/a` | not applicable to the observed tech stack |

Coverage = techniques actually attempted with evidence — never a
wish-list.

## 2. Workflow

1. **Profile** — from recon (OS, services, exposed tech) and the
   objective, select relevant tactics and techniques.
2. **Plan** — `killchain_lookup` pulls technique / threat-profile data;
   `killchain_suggest` proposes the next technique from current state.
3. **Emulate** — execute or coordinate each technique within RoE;
   record technique ID, procedure, and outcome.
4. **Map** — maintain the coverage layer as you go.
5. **Report** — emit the coverage summary; where a technique produced a
   reportable issue, write a finding and a scoped submission.

## 3. Tactic walk (Enterprise)

Initial Access → Execution → Persistence → Privilege Escalation →
Defense Evasion → Credential Access → Discovery → Lateral Movement →
Collection → Command and Control → Exfiltration → Impact. For each
tactic, list the techniques relevant to the recon-observed stack and
mark applicability.

## 4. Adversary emulation

Given a named threat profile, pull its TTPs with `killchain_lookup`,
order them with `killchain_suggest`, and emulate in sequence — recording
procedure + outcome per technique so the chain is reproducible.

## 5. Detection / purple-team validation

For each emulated technique, note the expected telemetry/detection and
whether it fired (when blue-team data is in scope). Output the
detection-gap list: techniques that succeeded with no corresponding
detection.

## 6. Rules

- Every claim carries its ATT&CK ID. No bare prose.
- Destructive Impact techniques (TA0040) are off-limits unless the
  engagement explicitly authorises them.
- Orchestrate and map; hand deep domain work (web, AD, cloud) to the
  matching specialist and record the handoff.
