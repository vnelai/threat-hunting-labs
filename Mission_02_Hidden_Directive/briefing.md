# Threat Hunt Briefing — Hidden Directive

> Source briefing as provided by the internship. Saved verbatim for reference. The report follows the "Final Report Requirements" structure below.

## Case
- **Case ID:** GF-INC-2026-0704
- **Company:** Greenfield Logistics
- **Type:** Full DFIR investigation
- **Goal:** Reconstruct the attack and produce an evidence-based incident report.
- **Known starting point:** GF-WS01 is compromised.
- **Hosts in scope:** GF-WS01, GF-SRV01, GF-DC01
- **Incident window:** 4 July 2026 10:00 UTC to 5 July 2026 03:00 UTC
- **Structure:** 13 investigation phases; no flags or points.

## Questions to Answer
- How the attacker entered
- What actions they performed
- Which hosts, users, and credentials were affected
- How far the attacker moved
- What data was accessed or stolen
- Which alerts were real or harmless
- Which security controls and detections should be added

## Telemetry Sources
1. **LAW-SilentCorridor — Microsoft Sentinel**
   - Primary source with longer retention
   - Covers all three hosts
   - Contains process, authentication, network, DNS, registry, named-pipe, and object-access logs
   - Host field: `DvcHostname`
2. **LAW-Cyber-Range — Defender XDR/MDE**
   - Detailed endpoint telemetry
   - Mainly covers GF-WS01 and GF-DC01
   - Important tables: `DeviceEvents`, `DeviceNetworkEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `SecurityAlert`
   - Host field: `DeviceName`
   - Approximately 30-day retention

Both sources must be checked because some attacker activity appears in only one.

## Query Rules
Every query must be filtered by the three Greenfield hosts and the incident time window.
Before using a table, inspect its fields (`TableName | take 1` or `TableName | getschema`). Do not guess field names.

## Investigation Approach
1. Filter the alert queue to the Greenfield hosts.
2. Identify clusters of related alerts.
3. Do not trust severity alone; Low alerts may matter and High alerts may be noise.
4. Record why each alert was accepted or dismissed.
5. Use alerts as starting clues.
6. Use raw telemetry to prove what happened.
7. Look earlier than the first alert because the attack may have already started.
8. Build a complete timeline with supporting queries and evidence.

## Important Baseline
GF-WS01 normally runs an internal AI page-summariser under a standard user account. It regularly downloads web content. The tool is legitimate, but its activity during the incident may not be. Treat it as: **Normal tool, potentially abnormal use.**

## Evidence Bag (five recovered artefacts)
| Artefact | Host / Source | SHA-256 |
|---|---|---|
| `blog_lure.html` | GF-WS01 | `ff7f87aedcdf2344abcf1a4dc7d0c8d1b62d2b33bab4f67ed2bb3396f4555199` |
| `loader.ps1` | GF-WS01 | `93164086788a0a8b5a16816922b631ff191ba1bdb5fd83cf25349ddc03af7583` |
| `shellcode_encoded.bin` | attacker infrastructure | `523f4c317e03cd1ac811fa7e1c308efd6df1e2a61048c1c0bdd5b4d5ffb73c34` |
| `gfupdater.exe` | GF-WS01 | `4713e5e9e54cb23c45aa608cb44e4137e915e3e963bd332136290ce85f9d4af9` |
| `hOQjiirI.exe` | GF-DC01 | `3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71` |

Verify every hash before analysis. Read the HTML and PowerShell as text. Perform static analysis only on binaries: file type, metadata, strings, headers, imports, and disassembly. **Do not execute the samples or upload them to VirusTotal or public sandboxes.**

## Final Report Requirements
- Executive summary
- Confirmed scope
- Detailed attack timeline
- Initial access and root cause
- Persistence, credential access, lateral movement, and collection
- Data accessed or stolen
- Host and account impact
- Artefact analysis
- MITRE ATT&CK mapping
- Supporting telemetry and KQL
- Dismissed alerts with reasoning
- Containment and recovery actions
- Recommended prevention and detection improvements

Clearly separate confirmed facts, reasonable conclusions, and unanswered questions. Every important claim should be tied to telemetry or an analysed artefact.
