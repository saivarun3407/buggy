# Known APT Group Quick Reference

Reference for selecting specific APT groups to emulate. Use this when the client requests simulation of a specific threat actor or when the engagement targets an industry with known adversaries.

## APT29 (Cozy Bear / Nobelium / Midnight Blizzard)

| Field | Detail |
|-------|--------|
| **Attribution** | Russia (SVR) |
| **Targets** | Government, technology, think tanks, diplomatic |
| **Motivation** | Espionage |
| **Sophistication** | Nation-state |
| **Notable** | SolarWinds supply chain (2020), OAuth abuse, cloud targeting |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain |
| T1078.004 | Valid Accounts: Cloud Accounts |
| T1550.001 | Use Alternate Authentication Material: Application Access Token |
| T1098 | Account Manipulation |
| T1071.001 | Application Layer Protocol: Web Protocols |
| T1059.001 | Command and Scripting Interpreter: PowerShell |

---

## APT41 (Winnti / Barium / Wicked Panda)

| Field | Detail |
|-------|--------|
| **Attribution** | China (MSS-linked) |
| **Targets** | Technology, gaming, healthcare, telecom |
| **Motivation** | Dual: espionage + financial |
| **Sophistication** | Nation-state |
| **Notable** | Supply chain attacks, rootkits, dual operations |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1195.002 | Supply Chain Compromise |
| T1059.001 | PowerShell |
| T1053.005 | Scheduled Task |
| T1574.001 | DLL Search Order Hijacking |
| T1070.004 | Indicator Removal: File Deletion |
| T1003.001 | OS Credential Dumping: LSASS Memory |

---

## FIN7 (Carbanak / Navigator Group)

| Field | Detail |
|-------|--------|
| **Attribution** | Eastern Europe (cybercriminal) |
| **Targets** | Retail, hospitality, financial services |
| **Motivation** | Financial |
| **Sophistication** | Medium-High |
| **Notable** | Point-of-sale malware, social engineering |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1566.001 | Phishing: Spearphishing Attachment |
| T1059.001 | PowerShell |
| T1059.005 | Visual Basic |
| T1053.005 | Scheduled Task |
| T1071.001 | Application Layer Protocol: Web |
| T1005 | Data from Local System |

---

## Lazarus Group (Hidden Cobra / ZINC)

| Field | Detail |
|-------|--------|
| **Attribution** | North Korea (RGB) |
| **Targets** | Financial, cryptocurrency, defense, media |
| **Motivation** | Financial + espionage |
| **Sophistication** | Nation-state |
| **Notable** | Cryptocurrency theft, watering holes, custom malware |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1189 | Drive-by Compromise |
| T1566.002 | Phishing: Spearphishing Link |
| T1059.006 | Python |
| T1055 | Process Injection |
| T1071.001 | Application Layer Protocol: Web |
| T1486 | Data Encrypted for Impact |

---

## APT28 (Fancy Bear / Sofacy / Strontium)

| Field | Detail |
|-------|--------|
| **Attribution** | Russia (GRU) |
| **Targets** | Government, military, media, political orgs |
| **Motivation** | Espionage + disruption |
| **Sophistication** | Nation-state |
| **Notable** | 0-day usage, credential harvesting, election interference |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1566.001 | Phishing: Spearphishing Attachment |
| T1190 | Exploit Public-Facing Application |
| T1078 | Valid Accounts |
| T1059.001 | PowerShell |
| T1003.001 | LSASS Memory Dump |
| T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol |

---

## Sandworm (APT44 / Voodoo Bear / Telebots / Seashell Blizzard) — G0034

| Field | Detail |
|-------|--------|
| **Attribution** | Russia (GRU Unit 74455, GTsST) |
| **Targets** | Energy/utilities, ICS/OT, government, NATO-aligned (esp. Ukraine) |
| **Motivation** | Disruption / sabotage + espionage |
| **Sophistication** | Nation-state |
| **Notable** | 2015/2016 Ukraine grid (BlackEnergy/Industroyer), NotPetya (2017), Olympic Destroyer (2018), Industroyer2 (2022) |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1190 | Exploit Public-Facing Application |
| T1566.001 | Phishing: Spearphishing Attachment |
| T1059.003 | Windows Command Shell (LOLBins: vssadmin, wbadmin, bcdedit) |
| T1485 | Data Destruction |
| T1561.002 | Disk Wipe: Disk Structure Wipe |
| T0831 | Manipulation of Control (ICS) |

---

## Volt Typhoon (Vanguard Panda / BRONZE SILHOUETTE / Insidious Taurus) — G1017

| Field | Detail |
|-------|--------|
| **Attribution** | China (PRC state-sponsored) |
| **Targets** | US critical infrastructure — communications, energy, water, transportation; pre-positioning toward OT |
| **Motivation** | Espionage / pre-positioning for disruptive effect |
| **Sophistication** | Nation-state |
| **Notable** | Living-off-the-land only (minimal malware), multi-year dwell, KV-botnet of compromised SOHO routers, edge-device exploitation |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1190 | Exploit Public-Facing Application (edge appliances) |
| T1078 | Valid Accounts |
| T1059.001 | PowerShell (LOTL) |
| T1003.003 | OS Credential Dumping: NTDS (ntdsutil / vssadmin) |
| T1070.001 | Indicator Removal: Clear Windows Event Logs |
| T1090.003 | Proxy: Multi-hop Proxy (SOHO router botnet) |

---

## Salt Typhoon (GhostEmperor / FamousSparrow / UNC2286) — G1045

| Field | Detail |
|-------|--------|
| **Attribution** | China (PRC state-sponsored) |
| **Targets** | Telecommunications / ISPs, lawful-intercept systems, government |
| **Motivation** | Espionage (long-term collection) |
| **Sophistication** | Nation-state |
| **Notable** | 2024 US telecom breaches (carrier backbones), network-edge persistence, custom web shells, log tampering |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1190 | Exploit Public-Facing Application (routers / firewalls / VPN) |
| T1098.004 | Account Manipulation: SSH Authorized Keys |
| T1021.004 | Remote Services: SSH |
| T1571 | Non-Standard Port |
| T1505.003 | Server Software Component: Web Shell |
| T1070 | Indicator Removal (log clearing) |

---

## Scattered Spider (UNC3944 / Octo Tempest / Roasted 0ktapus / Muddled Libra) — G1015

| Field | Detail |
|-------|--------|
| **Attribution** | eCrime (native English-speaking, US/UK) |
| **Targets** | Telecom, BPO/CRM, technology, gaming, hospitality, retail, financial, MSP |
| **Motivation** | Financial (extortion + ransomware) |
| **Sophistication** | High (social-engineering specialists) |
| **Notable** | MGM/Caesars (2023), help-desk vishing, MFA fatigue, SIM-swap, ALPHV→RansomHub→DragonForce affiliate |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1656 | Impersonation (help-desk / employee) |
| T1598 | Phishing for Information (vishing / smishing) |
| T1621 | Multi-Factor Authentication Request Generation (MFA fatigue) |
| T1078.004 | Valid Accounts: Cloud Accounts (Okta / Entra ID / AWS) |
| T1219 | Remote Access Software (AnyDesk / LogMeIn / ConnectWise) |
| T1486 | Data Encrypted for Impact |

---

## APT40 (Leviathan / Kryptonite Panda / Gingham Typhoon / TA423) — G0065

| Field | Detail |
|-------|--------|
| **Attribution** | China (MSS — Hainan State Security Dept.) |
| **Targets** | Maritime, defense, aerospace, government, critical infrastructure (APAC + US) |
| **Motivation** | Espionage |
| **Sophistication** | Nation-state |
| **Notable** | Rapid PoC weaponization (Log4Shell, ProxyShell, Confluence), compromised SOHO devices as C2 proxies, web shells |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1190 | Exploit Public-Facing Application |
| T1133 | External Remote Services |
| T1505.003 | Server Software Component: Web Shell |
| T1078 | Valid Accounts |
| T1090 | Proxy (compromised SOHO devices) |
| T1119 | Automated Collection |

---

## APT10 (Stone Panda / menuPass / Cicada / Red Apollo) — G0045

| Field | Detail |
|-------|--------|
| **Attribution** | China (MSS — Tianjin bureau) |
| **Targets** | Managed service providers (MSP), aerospace, government, healthcare, telecom |
| **Motivation** | Espionage |
| **Sophistication** | Nation-state |
| **Notable** | Operation Cloud Hopper (MSP supply-chain), PlugX / QuasarRAT, DLL side-loading, MSP→client pivot abusing trusted relationships |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1199 | Trusted Relationship (MSP pivot) |
| T1566.001 | Phishing: Spearphishing Attachment |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading |
| T1053.005 | Scheduled Task |
| T1003.001 | OS Credential Dumping: LSASS Memory |
| T1021.001 | Remote Services: Remote Desktop Protocol |

---

## OilRig (APT34 / Helix Kitten / Cobalt Gypsy / Hazel Sandstorm) — G0049

| Field | Detail |
|-------|--------|
| **Attribution** | Iran (MOIS) |
| **Targets** | Energy / oil & gas, financial, government, telecom, chemical (Middle East) |
| **Motivation** | Espionage |
| **Sophistication** | Nation-state |
| **Notable** | DNS-tunneling C2 specialists, custom backdoors (Helminth / QUADAGENT / Karkoff), web shells, heavy LOTL |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1566.001 | Phishing: Spearphishing Attachment |
| T1505.003 | Server Software Component: Web Shell |
| T1071.004 | Application Layer Protocol: DNS |
| T1572 | Protocol Tunneling (DNS tunneling) |
| T1059.001 | PowerShell |
| T1078 | Valid Accounts |

---

## MuddyWater (Mango Sandstorm / Static Kitten / Seedworm / TEMP.Zagros) — G0069

| Field | Detail |
|-------|--------|
| **Attribution** | Iran (MOIS) |
| **Targets** | Telecom, government, oil & gas, defense (Middle East); also an initial-access broker |
| **Motivation** | Espionage |
| **Sophistication** | High |
| **Notable** | Spearphishing → legitimate RMM (Atera / ScreenConnect / SimpleHelp), PowerShell-heavy tradecraft, BugSleep backdoor |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1566.002 | Phishing: Spearphishing Link |
| T1219 | Remote Access Software (RMM abuse) |
| T1059.001 | PowerShell |
| T1105 | Ingress Tool Transfer |
| T1534 | Internal Spearphishing |
| T1056.001 | Input Capture: Keylogging |

---

## Kimsuky (APT43 / Velvet Chollima / Emerald Sleet / THALLIUM) — G0094

| Field | Detail |
|-------|--------|
| **Attribution** | North Korea (RGB) |
| **Targets** | Think tanks, academia, nuclear / foreign-policy bodies, government, defense |
| **Motivation** | Espionage (+ crypto theft to fund operations) |
| **Sophistication** | High |
| **Notable** | Deep target recon, impersonation of journalists/academics, CHM lures, credential harvesting, email/session theft |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1598.003 | Phishing for Information: Spearphishing Link |
| T1566.002 | Phishing: Spearphishing Link |
| T1204.002 | User Execution: Malicious File (CHM) |
| T1056.001 | Input Capture: Keylogging |
| T1114 | Email Collection |
| T1539 | Steal Web Session Cookie |

---

## LockBit (RaaS) — no MITRE Group ID (tracked as software S1202)

| Field | Detail |
|-------|--------|
| **Attribution** | eCrime — Ransomware-as-a-Service (affiliate model) |
| **Targets** | Cross-sector — manufacturing, healthcare, financial, government, construction |
| **Motivation** | Financial (double extortion) |
| **Sophistication** | High (developer core + affiliates) |
| **Notable** | Most prolific RaaS of 2022–2023; StealBit/MEGA exfil; Windows + VMware ESXi lockers; disrupted by Operation Cronos (Feb 2024) |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1190 | Exploit Public-Facing Application |
| T1133 | External Remote Services (RDP / VPN) |
| T1486 | Data Encrypted for Impact |
| T1490 | Inhibit System Recovery (delete shadow copies) |
| T1562.001 | Impair Defenses: Disable or Modify Tools |
| T1567.002 | Exfiltration to Cloud Storage (StealBit / MEGA) |

---

## ALPHV / BlackCat (RaaS) — no MITRE Group ID (tracked as software S1068)

| Field | Detail |
|-------|--------|
| **Attribution** | eCrime — Ransomware-as-a-Service (DarkSide / BlackMatter successor) |
| **Targets** | Cross-sector incl. healthcare (Change Healthcare, 2024), energy, financial |
| **Motivation** | Financial (triple extortion) |
| **Sophistication** | High |
| **Notable** | Rust cross-platform locker (Windows / Linux / ESXi); stealer-sourced creds; Kerberoasting; AnyDesk / Splashtop / MEGAsync |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1078 | Valid Accounts (stealer-sourced credentials) |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting |
| T1021.001 | Remote Services: Remote Desktop Protocol |
| T1486 | Data Encrypted for Impact |
| T1490 | Inhibit System Recovery |
| T1567.002 | Exfiltration to Cloud Storage |

---

## Cl0p (TA505 / FIN11 overlap) — G0092 (software S0611)

| Field | Detail |
|-------|--------|
| **Attribution** | eCrime (TA505-linked) |
| **Targets** | Mass cross-sector via managed file transfer — financial, healthcare, government, education |
| **Motivation** | Financial (data-theft extortion) |
| **Sophistication** | High |
| **Notable** | Mass 0-day of MFT appliances (MOVEit CVE-2023-34362, GoAnywhere CVE-2023-0669, Accellion FTA, Cleo); LEMURLOOT web shell; shift to extortion-only |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1190 | Exploit Public-Facing Application (MFT 0-days) |
| T1505.003 | Server Software Component: Web Shell (LEMURLOOT) |
| T1567 | Exfiltration Over Web Service |
| T1486 | Data Encrypted for Impact |
| T1078 | Valid Accounts |
| T1133 | External Remote Services |

---

## Turla (Snake / Venomous Bear / Waterbug / Secret Blizzard) — G0010

| Field | Detail |
|-------|--------|
| **Attribution** | Russia (FSB Center 16) |
| **Targets** | Government, diplomatic, military, research — 50+ countries |
| **Motivation** | Espionage |
| **Sophistication** | Nation-state |
| **Notable** | Snake/Uroburos implant (FBI Operation MEDUSA takedown, 2023), satellite-link C2, watering holes, hijacks other actors' infrastructure |

**Key TTPs:**
| ID | Technique |
|----|-----------|
| T1584.004 | Compromise Infrastructure: Server (hijacked relays) |
| T1189 | Drive-by Compromise (watering hole) |
| T1071.001 | Application Layer Protocol: Web Protocols |
| T1505.003 | Server Software Component: Web Shell |
| T1027 | Obfuscated Files or Information |
| T1070 | Indicator Removal |

---

## Industry → Likely Threat Actors

Quick lookup for engagement scoping:

| Target Industry | Primary Threat | Secondary Threat |
|----------------|---------------|-----------------|
| Financial / banking | FIN7, Lazarus (APT38) | LockBit, Cl0p, ALPHV |
| Government / diplomatic | APT29, APT28 | Turla, Volt Typhoon, Kimsuky |
| Technology / SaaS | APT41, APT29 | Scattered Spider, FIN7 |
| Healthcare / pharma | ALPHV, LockBit | APT41, Cl0p |
| Defense / aerospace | APT28, APT40 | Lazarus, APT10, Turla |
| Maritime / shipping | APT40 | APT41 |
| Retail / hospitality / gaming | FIN7, Scattered Spider | LockBit |
| Cryptocurrency / DeFi | Lazarus (incl. AppleJeus) | Kimsuky |
| Energy / utilities | Sandworm, OilRig | APT28, Volt Typhoon |
| ICS / OT / critical infra | Sandworm, Volt Typhoon | APT40 |
| Telecom / ISP | Salt Typhoon, MuddyWater | APT41, APT10 |
| Manufacturing / industrial | LockBit, ALPHV | APT41 |
| MSP / IT services / supply chain | APT10, APT29 | Cl0p, Scattered Spider |
| Education / research | Cl0p, Kimsuky | APT41 |
| Think tanks / NGO / policy | Kimsuky, APT29 | APT28, Turla |

---

## MITRE ATT&CK Group ID crosswalk

Fill `threat-profile.json` → `group_id` from this table. Ransomware crews tracked
by MITRE as *software* rather than a *group* have no `Gxxxx`; leave `group_id` empty
and set `actor_name` to the crew name + software ID.

| Actor | MITRE ID | Attribution | Type |
|-------|----------|-------------|------|
| APT29 | G0016 | Russia (SVR) | Nation-state espionage |
| APT28 | G0007 | Russia (GRU 26165) | Nation-state espionage/disruption |
| Sandworm | G0034 | Russia (GRU 74455) | Nation-state disruption/ICS |
| Turla | G0010 | Russia (FSB) | Nation-state espionage |
| APT41 | G0096 | China (MSS) | Nation-state + financial |
| APT40 | G0065 | China (MSS Hainan) | Nation-state espionage |
| APT10 | G0045 | China (MSS Tianjin) | Nation-state / supply chain |
| Volt Typhoon | G1017 | China (PRC) | Nation-state / critical infra |
| Salt Typhoon | G1045 | China (PRC) | Nation-state / telecom |
| OilRig (APT34) | G0049 | Iran (MOIS) | Nation-state espionage |
| MuddyWater | G0069 | Iran (MOIS) | Nation-state / access broker |
| Lazarus Group | G0032 | North Korea (RGB) | Nation-state + financial |
| APT38 (BlueNoroff) | G0082 | North Korea (RGB) | Nation-state financial |
| AppleJeus | G1049 | North Korea (RGB) | Crypto theft (Lazarus umbrella) |
| Kimsuky (APT43) | G0094 | North Korea (RGB) | Nation-state espionage |
| FIN7 | G0046 | eCrime | Financial → ransomware (BGH) |
| Scattered Spider | G1015 | eCrime | Social-engineering extortion |
| Cl0p (TA505) | G0092 | eCrime | MFT mass-exploitation extortion |
| LockBit | — (software S1202) | eCrime RaaS | Ransomware (affiliate) |
| ALPHV / BlackCat | — (software S1068) | eCrime RaaS | Ransomware (affiliate) |

## Tier mapping & emulation playbooks

Map each actor to a `ThreatProfile.tier` before writing the profile:

| Tier | Value | Fits |
|------|-------|------|
| 3 | `tier-3` | All nation-state actors above (APT29/28, Sandworm, Turla, APT41/40/10, Volt/Salt Typhoon, OilRig, MuddyWater, Lazarus, Kimsuky) |
| 2 | `tier-2` | Targeted eCrime (FIN7, Scattered Spider, LockBit/ALPHV/Cl0p affiliates) |
| 1 | `tier-1` | Opportunistic / commodity (see `adversary-archetypes.md`) |

For full kill-chain emulation plans that translate these profiles into Buggy
OPPLAN objectives + the operational skills each phase uses, load the emulation
catalog: `load_skill("/skills/standard/soundwave/threat-profile/emulation/SKILL.md")`.
