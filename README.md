# Threat Hunting Labs

Hands-on threat hunting work in Microsoft Sentinel and Microsoft Defender for Endpoint (MDE), correlating authentication, process, and file telemetry to investigate suspicious activity and determine root cause. Each mission is a self-contained lab with its own report, screenshots, and raw query exports.

_Defensive security work by Virginia Nelai, performed on the LOG(N) Pacific Cyber Range._

---

## Labs

**Mission 01: Just Another Day, Valid Account Compromise** ([report](Mission_01_Just_Another_Day/report.md))
Investigated suspicious remote access to a billing analyst account at Nimbus Health (scenario org). Pivoted across `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceEvents` to trace authentication from an external public IP, LOLBin-based reconnaissance, lateral movement to a file server, and collection of payroll/HR documents. Root cause: valid account compromise, not insider misuse.

**Mission 02: Hidden Directive, AI Prompt Injection to Domain Compromise** ([report](Mission_02_Hidden_Directive/report.md) · [full incident report](Mission_02_Hidden_Directive/Report/GF-INC-2026-0704_Incident_Report.md))
Full DFIR investigation at Greenfield Logistics (scenario org) across three hosts. An internal AI page-summarizer read a booby-trapped web page and executed hidden instructions embedded in it, no human had to click anything. Traced the intrusion from that initial prompt injection through defense evasion, four separate persistence mechanisms, an LSASS memory-access credential theft, and lateral movement into the domain controller, correlating across Sentinel and Defender XDR with KQL. 20+ ATT&CK techniques mapped. Includes a Lessons Learned section from a follow-up debrief: what held up and what I'd correct.

---

## Skills Demonstrated

Microsoft Sentinel and Microsoft Defender for Endpoint (MDE) investigation, KQL query authoring, cross-table evidence correlation, workspace/time/host scoping, Living-Off-The-Land (LOLBin) technique identification, lateral movement tracing, data collection analysis, MITRE ATT&CK mapping, root cause assessment, static malware/artifact analysis, AI prompt-injection attack analysis.

## About
Part of my cybersecurity portfolio. More: [github.com/vnelai](https://github.com/vnelai)
