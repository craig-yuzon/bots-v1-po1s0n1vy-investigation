# BOTS v1 Investigation: Web Compromise and Cerber Ransomware

An incident response triage and Splunk investigation of a multi-stage attack on a simulated company, written up the way a SOC analyst would hand it to L2/L3.

**Verdict:** True Positive, **Critical**, escalated. A public-facing Joomla web server was compromised and defaced, and weeks later an internal workstation was infected with Cerber ransomware that spread over SMB to a file server (658 files encrypted).

> **About the data:** This is an investigation of Splunk's public training dataset, [Boss of the SOC v1 (BOTS)](https://github.com/splunk/botsv1). The company, hosts, users, and WHOIS persona are all part of that exercise. Nothing here involves a real organization or a real person.

## What this repo shows

| Skill | Where to see it |
|---|---|
| Alert triage and severity/disposition decisions | `report/` |
| Splunk SPL (stats, rex, transaction, dedup, lookups) | `queries/` |
| Log correlation across HTTP, firewall, IDS, Sysmon, and registry data | `report/`, `evidence/` |
| OSINT pivoting (VirusTotal, WHOIS history) | `report/` |
| MITRE ATT&CK mapping | `report/` |
| Turning findings into IR, prevention, and detection recommendations | `report/` |

## Investigation at a glance

### Phase 1: Web server compromise (August 10, 2016)
- Scanning of `imreallynotbatman.com` identified as **Acunetix WVS 10.0**; the CMS is **Joomla**.
- **412 unique passwords** were tried against the Joomla admin login with a Python-based tool. The correct password, `batman`, is a weak, guessable choice.
- A malicious executable, `3791.exe`, was uploaded through the admin panel (MD5 `AAE3F5A29935E6ABCC2C2754D12A9AF0`).
- The site was defaced with an image pulled from attacker-controlled infrastructure.
- **Confidence:** High for the scanning, brute force, upload, and defacement (direct log evidence). Moderate for attribution to the Po1s0n1vy group (based on infrastructure overlap and OSINT, not a single definitive artifact).

### Phase 2: Cerber ransomware (August 24, 2016)
- Workstation `we8105desk` visited a compromised site and downloaded `mhtr.jpg`, an image with the Cerber cryptor hidden inside it (**steganography**).
- `20429.vbs` ran through `wscript.exe` and launched the payload `121214.tmp` from the user's AppData folder.
- The host contacted a Cerber C2 domain, then encrypted **401 `.txt` files** locally and spread over **SMB** to the file server, encrypting **257 `.pdf` files**.
- A USB device (`MIRANDA_PRI`) appears in the registry data. It is flagged as a **suspected** infection vector, not a confirmed one.
- **Confidence:** High for the infection chain and impact. The link between Phase 1 and Phase 2 is **assessed, not proven**: both occurred in the same environment, but the logs do not show a direct pivot from the web server to the workstation.

## MITRE ATT&CK techniques observed
T1595.002 (Vulnerability Scanning), T1190 (Exploit Public-Facing Application), T1110 (Brute Force), T1105 (Ingress Tool Transfer), T1491.002 (External Defacement), T1059.005 (Visual Basic), T1027.003 (Steganography), T1021.002 (SMB/Windows Admin Shares), T1486 (Data Encrypted for Impact), T1091 (Replication Through Removable Media, suspected)

## Repo structure
```
.
├── README.md
├── report/        IR triage report (PDF + Markdown)
├── queries/       SPL used in each phase
└── evidence/      Cropped Splunk and OSINT screenshots, numbered in story order
```

## Tools
Splunk (index `client1`), Suricata IDS alerts, Sysmon, Windows registry logs, FortiGate logs, VirusTotal, WHOIS history lookups, CyberChef.

## Key recommendations (full list in the report)
- **Detect:** correlate bursts of POSTs to a login page with a later success; alert on a `.jpg` download followed by script execution; alert when `wscript.exe` spawns child processes or makes network connections.
- **Prevent:** MFA and lockout on admin panels, restrict SMB between workstations and file servers, block script hosts and AppData execution where not needed, USB device control.
- **Respond:** isolate the workstation, web server, and file server; preserve encrypted files before any restore; reset all Joomla admin credentials.

## Author
**Craig Yuzon** — aspiring SOC Analyst. https://www.linkedin.com/in/craig-yuzon/
