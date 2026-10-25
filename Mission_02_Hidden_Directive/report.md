# Mission 02: Hidden Directive

**Case:** GF-INC-2026-0704 · Greenfield Logistics (scenario org)
**Date:** 2026-07-26
**Tools:** Microsoft Sentinel (KQL), Microsoft Defender for Endpoint (MDE), static artifact analysis
**Track:** A, Cyber Hunt / SOC
**Analyst:** Virginia Gina Nelai

Greenfield Logistics asked me to reconstruct a full intrusion across three hosts: a workstation, a member server, and the domain controller. The attacker's way in wasn't a phishing email or a stolen password. It was an AI tool doing exactly what it was built to do. This is that investigation, the evidence behind it, and what I'd fix.

Full incident report (32-page formal DFIR write-up, every claim tied to telemetry): [GF-INC-2026-0704_Incident_Report.md](Report/GF-INC-2026-0704_Incident_Report.md)

---

## The way in

Greenfield had a small AI tool called `mshealth.py` running on one workstation (`GF-WS01`) that reads web pages and summarizes them for people. The attacker hid instructions inside a fake blog post (`blog_lure.html`), written so an AI reading it would follow them instead of just summarizing it. The tool read the page, and in doing that, it ran the attacker's first command: a command that told the AI to contact the attacker's server (`cdn.cloud-endpoint.net`) and follow whatever instructions came next. This attempt at entry didn't need a human to click on anything.

![html-lure](screenshots/html-lure.png)
*`blog_lure.html`, read as plain text in an isolated, network-disconnected VM. The visible content is a decoy blog post. The real payload is an HTML comment addressed directly to an AI reader, instructing it to run PowerShell silently and hide that it did so.*

## Staying in, and shutting off the alarm

Once in, the attacker's first priority wasn't stealing anything, it was making sure they couldn't be kicked out. Using an account called `sancadmin`, they set up four separate, independent ways back into GF-WS01: a boot-triggered scheduled task, a logon-triggered scheduled task, a registry Run key, and a hijacked system service (`GFUpdaterSvc`, its real binary quietly swapped out for the attacker's own). Any one of those alone survives a normal cleanup. They also disabled Windows Defender entirely, disguised as routine maintenance, hours before anything else in the timeline.

The recurring hourly download behind all of this traces back to `loader.ps1`, a PowerShell shellcode loader recovered from GF-WS01. It patches PowerShell's own AMSI antivirus hook so the runtime believes scanning already failed, downloads its payload from the same attacker domain, decodes it, and runs it directly in memory. No file ever touches disk for that stage.

![cat-loader-ps1-fulltext](screenshots/cat-loader-ps1-fulltext.png)
*`loader.ps1`, full text, analyzed in the same isolated VM, never executed. The AMSI bypass, the download URL, and the in-memory execution logic all live here.*

![persistance](screenshots/persistance.png)
*The full GF-WS01 persistence sequence: scheduled task creation, registry Run key, and the `GFUpdaterSvc` stop/copy/start that swapped in the attacker's binary.*

## Calling home

With the workstation theirs, the attacker set up two separate ways to keep talking to it. One was fully automated: a piece of malware called AdaptixC2, loaded straight into memory, never written to disk, checking in with the attacker's server on its own. The other was hands-on: AnyDesk, a legitimate remote-access tool already used by staff, reconfigured by a second compromised account (`t.harris`, on `GF-SRV01`) with a backdoor password so the attacker could reconnect any time, no Windows login required.

![virustotal-cloud-endpoint-domain-check](screenshots/virustotal-cloud-endpoint-domain-check.png)
*`cloud-endpoint.net`, the domain behind both the loader and the AdaptixC2 traffic, checked as a URL/domain lookup on VirusTotal. Flagged malicious by multiple vendors.*

## Grabbing more power

The attacker needed to run code as the most powerful account on the machine, and found two separate ways to get there, on two different hosts. On `GF-WS01`, `sancadmin` already had admin rights and used them to plant a SYSTEM-level scheduled task and hijack a service. On `GF-SRV01`, `t.harris` found the SQL Server instance still had a known dangerous setting available to turn on (`xp_cmdshell`), and used it to run commands straight through the database engine. Neither move used an exploit. Both just relied on things being configured more openly than they should have been.

![goldmine-harris](screenshots/goldmine-harris.png)
*`t.harris`'s full command-line sequence on GF-SRV01: a privilege-escalation misconfiguration check (`AlwaysInstallElevated`), followed by enabling and testing `xp_cmdshell`.*

## Stealing the keys

From there they went after credentials, and found them sitting around in more than one place. On `GF-WS01`, `sancadmin` found a service account's password (`svc_backup`) left readable in Active Directory's Description field, a plain internal notes field that should never hold a password, and it was found and used within half an hour. `sancadmin` also used a trick where a normal Windows program (Explorer) briefly touched the memory of the process that holds every logged-in user's credentials (`lsass.exe`), and Windows' own crash-reporting tool (`WerFault`), running with full system rights, touched that same memory again a second later. That's a way to get a trusted part of Windows to do the actual credential theft on the attacker's behalf.

On `GF-SRV01`, `t.harris` went further: they changed `svc_backup`'s password outright, and a second employee's actual password (`d.williams`, `ITAdmin2025!`) showed up typed directly into one of their commands, in plain, readable text, and got used right there. How they got hold of that password in the first place isn't confirmed, only that they had it and used it.

![credential-sniffing](screenshots/credential-sniffing.png)
*`sancadmin`'s full command-line sweep on GF-WS01: checking Credential Manager, then four separate attempts to read `svc_backup`'s AD Description field.*

![mde-lsaas](screenshots/mde-lsaas.png)
*Two processes touching `lsass.exe` a fraction of a second apart: `explorer.exe` under `sancadmin`, then `WerFault.exe` running as SYSTEM, the crash-dump credential-theft pattern.*

## Reaching the domain controller

With stolen credentials in hand, the attacker moved from `GF-WS01` to `GF-SRV01`, and then from `GF-SRV01` to `GF-DC01`, the domain controller, which holds every account and password for the entire company. Second by second, the logs show the compromised account `d.williams` logging into `GF-DC01`, immediately accessing an administrative file share, and then triggering Windows' own service-installer to plant and run a malicious program, all inside an eight-second window. The log event that records the service being installed names the account that did it directly, so this is confirmed from the log itself.

![williams-sec-event](screenshots/williams-sec-event.png)
*The service-installation event on GF-DC01, `SubjectUserName: d.williams`, direct attribution straight from the log.*

![hOQjiirI](screenshots/hOQjiirI.png)
*`services.exe` launching the planted executable at 15:00:39 UTC, matching a known Impacket remote-execution pattern.*

## What I checked and didn't find

Once I knew they'd reached `GF-DC01`, the next question was whether they'd obtained a full copy of the domain's password database (`NTDS.dit`). I checked for the three standard tools someone would use to pull that off, and none of them show up anywhere. They didn't touch it. Three automated alerts also claimed the attacker had bundled up company files to steal them. I checked what was actually happening behind each one, and none of it holds up against the process telemetry. So right now: no proof any data left the building, but no proof it didn't either. That one's still open.

---

## How I found it

I started in the Defender portal's alert queue, scoped down to the three Greenfield hosts with an entity filter (both case variants of each hostname included, since the tenant listed them inconsistently).

![alert-queue-entity-filter](screenshots/alert-queue-entity-filter.png)
*Entity filter set to all six host-entity variants, severity left unfiltered so nothing got screened out before I could look at it myself.*

Defender groups related events into a single alert with separate First and Last activity times, so I sorted the queue by First activity ascending instead of by detection order. That's what let me catch activity sitting before the first alert ever fired.

![sl-linux-beaconing-alerts-sorted-first-activity](screenshots/sl-linux-beaconing-alerts-sorted-first-activity.png)
*One repeating alert type sorted to the top of the timeline once I sorted this way, a recurring hourly pattern going back further than the stated incident window.*

That alert looked like shared cyber-range noise at first, other tenants running the same generic detection rule. But `GF-WS01` turned out to be hiding among the seven flagged devices, and it was the only one of the seven running `python.exe`, the same process behind `mshealth.py`, the AI summarizer tool at the center of this whole case.

![sl-linux-beaconing-impacted-devices-list](screenshots/sl-linux-beaconing-impacted-devices-list.png)
*The device list behind that alert, `GF-WS01` sitting among six unrelated hosts, both its rows running `python.exe` against the same script.*

I also picked up an early alert claiming the attacker had bundled up files on `GF-WS01` for theft. Robocopy had run with a mirror flag, which matched the rule. But the folder being mirrored was Prefetch, a Windows OS artifact folder, not business data, so I kept that one open as an unresolved question rather than either accepting or dismissing it on the alert name alone.

![gfd-staging-robocopy-gf-ws01-collection-alert](screenshots/gfd-staging-robocopy-gf-ws01-collection-alert.png)
*The staging alert on `GF-WS01`, expanded to show the actual robocopy command line rather than trusting the rule's own description of it.*

The GUI wouldn't let me filter a single multi-device alert down to just the Greenfield hosts, so partway through I moved into Sentinel and Defender's Advanced Hunting directly, running table-discovery queries in both workspaces first to confirm real field names before writing anything more specific.

![kql-table-discovery-law-silentcorridor](screenshots/kql-table-discovery-law-silentcorridor.png)
*Table discovery in Sentinel (LAW-SilentCorridor), bucketing every table by event count. This is what confirmed real field names like `TargetProcessCommandLine`, instead of guessing.*

![kql-table-discovery-law-cyber-range](screenshots/kql-table-discovery-law-cyber-range.png)
*Same discovery query against the Defender workspace (LAW-Cyber-Range), confirming its own separate table set.*

One of those discovery queries corrected something in the original briefing. It described Defender's coverage as mainly `GF-WS01` and `GF-DC01`, but a straight per-host count showed `GF-SRV01` with the most process events of the three.

![kql-deviceprocessevents-per-host-count](screenshots/kql-deviceprocessevents-per-host-count.png)
*Process event counts by host: GF-SRV01 ahead of both GF-WS01 and GF-DC01, correcting the briefing's own scope description.*

Filtering Sentinel's `SecurityAlert` table to just the alerts prefixed `GFD`, Greenfield's own custom rule set rather than another tenant's, cut a 175-alert queue down to 29 and handed me a clean, ground-truth timeline in one query.

![gfd-securityalert-full-timeline-1-16](screenshots/gfd-securityalert-full-timeline-1-16.png)
*The `GFD`-prefixed alert timeline, sorted ascending, the actual scenario signal separated from every other tenant's noise in one filter.*

A parallel pull from Defender's `AlertInfo` table named the malware and the toolkit directly: AdaptixC2 and Impacket, both confirmed active on the estate rather than guessed at from behavior alone.

![alertinfo-edr-av-timeline-1-16](screenshots/alertinfo-edr-av-timeline-1-16.png)
*EDR/Antivirus-sourced detections, sorted by first-seen time, naming AdaptixC2 and Impacket directly.*

Joining that same table to `AlertEvidence` fixed a duplicate-row bug and attached a real hostname and a real MITRE technique ID to every row. That's what turned "probably GF-SRV01" into a confirmed fact instead of a guess.

![alertinfo-joined-with-device-1-15of36](screenshots/alertinfo-joined-with-device-1-15of36.png)
*The same alert data, joined to real device names and ATT&CK technique IDs, showing the AdaptixC2 backdoor and the human-operated activity following the attacker onto GF-SRV01.*

The LSASS credential-theft finding held up because it showed up twice, independently, once in Sentinel and once in Defender's own native telemetry: same second, same account, same access mask, two separate logging pipelines agreeing on every detail.

![lsass-cmd](screenshots/lsass-cmd.png)
*The Sentinel-side version of the LSASS access event, `sancadmin` via `Explorer.EXE`, cross-confirming the Defender-side finding shown earlier.*

---

## MITRE ATT&CK coverage

| Tactic | Representative Techniques |
|---|---|
| Initial Access | Prompt injection into an AI-driven automation tool (unmapped, novel vector) |
| Execution | T1059.001 (PowerShell), T1047 (WMI) |
| Persistence | T1053.005 (Scheduled Task), T1547.001 (Registry Run Keys), T1543.003 (Windows Service) |
| Privilege Escalation | T1012 / T1059 (misconfiguration abuse via `AlwaysInstallElevated`, `xp_cmdshell`) |
| Defense Evasion | T1562.001 (Impair Defenses), T1055 / T1055.001 (Process Injection) |
| Credential Access | T1552 (Unsecured Credentials), T1003.001 (LSASS Memory), T1098 (Account Manipulation), T1078 (Valid Accounts) |
| Discovery | T1087.002, T1018, T1033, T1049, T1518 |
| Lateral Movement | T1021.002 (SMB/Admin Shares), T1210 (Exploitation of Remote Services) |
| Command and Control | T1219 (Remote Access Software), AdaptixC2 (in-memory, unmapped) |
| Ingress Tool Transfer | T1105 |

Full mapping with evidence references for every row is in the complete report (Section 6).

---

## Skills demonstrated

Microsoft Sentinel and Defender XDR/MDE investigation, KQL query authoring against real (not assumed) schemas, cross-table evidence correlation, static analysis of malicious HTML/PowerShell artifacts in an isolated VM, MITRE ATT&CK mapping, root cause and impact assessment, and identifying a prompt-injection attack against an internal AI automation tool as a genuine, novel entry point rather than a conventional phishing or credential-based one.

## What I learned doing this

A few things clicked for me during this hunt that I want to hold onto. Defender groups related events into one alert with separate First and Last activity times, so sorting by First activity ascending instead of by detection order is what actually let me catch activity that happened before the first alert fired. A "High severity" tag or a big device count on an alert doesn't tell you anything on its own, I had to open the alert and check the real device list before I could trust or dismiss it, that's what separated real range noise from an actual Greenfield host. I also got burned once guessing a KQL field name that didn't exist, now I run `getschema` first every time, no exceptions. And a clean negative, like checking for the tools that would pull the domain's password database and finding none of them, turned out to be real evidence worth writing down, not just an empty result. An alert's own rule description isn't proof of anything either, the robocopy "staging" alert matched the rule's trigger, but the folder actually being mirrored was an OS artifact folder, not business data, so the alert name alone would have pointed me the wrong way.

## Lessons Learned (Debrief Follow-Up)

After I submitted this report, the internship lead sent back a detailed debrief. Sharing it here because I think what I got wrong is as useful as what I got right, and because closing a real gap in an investigation is worth being upfront about, not something to bury.

**What held up:** the core investigation, the initial access via the AI prompt injection, the persistence mechanisms, the credential sources, the implant, all traced correctly with accurate timestamps. I was also deliberately careful anywhere I wasn't sure: if something wasn't confirmed, I marked it unresolved instead of guessing, and if evidence was missing, I checked that I'd actually looked hard enough before trusting the absence.

**What didn't hold up, three things I called with more confidence than I'd earned:**

- I flagged `WerFault.exe` (Windows' built-in crash reporter) as a deliberate technique the attacker used to steal credentials. It wasn't. It was just Windows automatically responding to a crash caused by something else I'd already identified. I recognized the *shape* of a known technique without confirming it was actually happening here.
- I called a task named `GFDefenderMaintenance` a fourth persistence mechanism the attacker planted. It's the company's own legitimate IT maintenance tooling. I also said the attacker disabled Windows Defender during the intrusion, but Defender itself had already caught and shut that down hours before my investigation window even started.
- The real cost: I found the command that zipped up files for exfiltration (`Compress-Archive`), searched for it inside a specific time window, didn't see it there, and cleared it as a false positive, no data stolen. It ran just outside the window I was checking. That's the actual data theft in this incident, and I closed the door on it.

I also never checked for two ways the attacker could have kept permanent access across the whole domain, not just one machine (AdminSDHolder and DCSync abuse). Because I didn't look, my impact assessment read lighter than the intrusion actually was.

**The pattern, and what I'm taking forward:** I was rigorous about proving something was truly *absent* before I trusted it. I wasn't equally rigorous about proving something was truly *present*, or double-checking my search window before I *cleared* something as a non-issue. Same standard, applied unevenly. Going forward, before I promote a finding or close one out, I check it against the underlying evidence with the same skepticism I already apply to gaps, not less.

---

*This is a simulated incident, conducted on the LOG(N) Pacific Cyber Range as part of a cybersecurity internship. All findings are based on telemetry and artifacts from the fictional Greenfield Logistics training estate.*
