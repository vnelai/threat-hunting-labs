# Threat Hunting Labs

Hands-on threat hunting work in Microsoft Sentinel and Microsoft Defender for Endpoint (MDE), correlating authentication, process, and file telemetry to investigate suspicious activity and determine root cause. Each mission is a self-contained lab with its own report, screenshots, and raw query exports.

_Defensive security work by Virginia Nelai, performed on the LOG(N) Pacific Cyber Range._

---

## Labs

**Mission 01: Just Another Day, Valid Account Compromise** ([report](Mission_01_Just_Another_Day/report.md))
Investigated suspicious remote access to a billing analyst account at Nimbus Health (scenario org). Pivoted across `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceEvents` to trace authentication from an external public IP, LOLBin-based reconnaissance, lateral movement to a file server, and collection of payroll/HR documents. Root cause: valid account compromise, not insider misuse.

---

## Skills Demonstrated

Microsoft Sentinel and Microsoft Defender for Endpoint (MDE) investigation, KQL query authoring, cross-table evidence correlation, workspace/time/host scoping, Living-Off-The-Land (LOLBin) technique identification, lateral movement tracing, data collection analysis, MITRE ATT&CK mapping, root cause assessment.

## About
Part of my cybersecurity portfolio. More: [github.com/vnelai](https://github.com/vnelai)
