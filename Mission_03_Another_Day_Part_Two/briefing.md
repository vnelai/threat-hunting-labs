# Threat Hunt Briefing — Another Day, Part Two

> Source briefing as provided by the internship. Saved verbatim for reference. The report follows the same structure as prior missions in this series.

## Case
- **Title:** Another Day, Part Two
- **Company:** Nimbus Health (scenario org — same client as Mission 01, "Just Another Day," March incident)
- **Difficulty:** Beginner (harder edge than part one)
- **Platform:** Windows estate — billing, HR, clinical, IT
- **Telemetry:** Microsoft Sentinel // MDE
- **Profile:** External credential reuse // HR collection
- **Scope:** `nh-wks-it-01` — single host
- **Window:** 25 to 30 May 2026
- **Structure:** Gate (Section 00) + 6 phases, 19 flags
- **Method:** OSINT + telemetry

## Review Assignment (Hunt Lead → On-Shift)

Nimbus Health, the outpatient clinic worked in March (part one), is back. A nearby industrial park opened; patient volume grew, and so did billing, HR onboarding, and endpoint support. Nimbus hired across every department at once and put new starters on the same shared workstations already in use. Growth first, access review later.

During a routine credential exposure sweep, one of those new hires was flagged: his identity is sitting in public, and so is an old password of his. In the same period, authentication telemetry on one of their machines shows failed logons against that account, then a success.

**What we need to work out:**
- How the account was found and why it was worth targeting
- Whether the credentials were actually used, and from where
- What happened once someone was on the keyboard
- What the account reached outside its role, and where that material went
- Whether anything was left behind, and the honest root cause

**Telemetry:** `law-cyber-range` Sentinel workspace, MDE tables: `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceEvents`.

This one starts outside the SIEM. Some of the earliest answers are not in any log — they are in what the internet already knows about this man. Work the OSINT artefacts before writing the first query.

**Filter, or drown.** Shared workspace, three ways to lose yourself:
- Bind every query to **25–30 May 2026**.
- Scope to `DeviceName startswith "nh-wks-it-01"` (the device is registered under its FQDN — use `startswith`, not `==`).
- Filter to the account under review.
- Results running into March = the part-one incident, not this one.
- A wall of failed logons from dozens of addresses = the open internet hammering the box, not the intruder.

**Two things to hold from the start:**
1. The loudest thing in the data is not the story. The box is under constant brute-force noise, and almost none of it goes anywhere.
2. Not every deletion is a cover-up. Windows and its applications tidy up after themselves constantly. Learn to tell a machine apart from a person.

**Work it end to end.** Reconstruct what happened, in order, and be careful where the anchor is set. A session opening is not the same as somebody starting work. Reason where the evidence is thin, and be ready to prove that something did *not* happen.

**Gate phrase:** Section 00 is a gate — confirm the right workspace, scoped to the right window and the right host, before starting. The phrase to submit is in the brief: **"Nimbus support review ready."**

— Hunt Lead, Cyber Range SOC · Nimbus Health series, part two

## Open-Source Artefacts (work these first)

Four items were recovered during the exposure sweep. Between them they explain how a stranger picked this account out of a small clinic, why an old password still worked, and which machine was worth pointing it at. None of them are from the SIEM.

- Evidence bag: https://hunt.lognpacific.com/hunt-14-evidence

## Workspace
All telemetry lives in the `law-cyber-range` Sentinel workspace.
- https://portal.azure.com/#view/Microsoft_Azure_Security_Insights/MainMenuBlade/~/3/id/%2Fsubscriptions%2F3c95e63a-895a-4386-991e-edbbf57de5c8%2Fresourcegroups%2Fcyber-range-admin-soc%2Fproviders%2Fmicrosoft.securityinsightsarg%2Fsentinel%2Flaw-cyber-range

Confirm access, and hold the May window and `nh-wks-it-01` (`startswith`) filter on every query.

## Method (not answers)

01. **Start outside the SIEM.** The first answers are in the artefacts, not the logs. Identity, then exposure, then the machine that was reachable.
02. **Filter first, every time.** May window, single host, one account. Results in March belong to part one. Results on other `nh-*` hosts are not yours.
03. **Volume is not signal.** Thousands of failures from dozens of addresses is the internet being the internet. Look for the source that is patient, targeted, and eventually succeeds.
04. **Mind your anchor.** A session opening is not a person starting work. Profile creation and first-run application noise sit in between. Anchor on the first real command.
05. **Read strings off the log line.** Do not rebuild a group name or a path from what you assume the naming convention is. Copy what is actually there.
06. **Check the role before calling it abuse.** The matrix tells you what this account is entitled to. Abuse is what sits outside it.
07. **Follow the data out.** Not everything leaves over the network in a way you'd think to query. Ask what channel was already open.
08. **Prove the negatives.** Two findings here are things that did not happen. Do not assume them — evidence them, and account for what was found instead.

## Hunt Stages (Gate + 6 phases)

- **00 — Setup gate:** confirm the `law-cyber-range` workspace, the May window, and the `nh-wks-it-01` filter (`startswith`, not exact match). Acknowledge with the phrase from this brief.
- **01 — Who they went after, and why:** the account, what is public about him, and which exposure actually handed someone a working password.
- **02 — Getting in:** cutting the real attempt out of the noise floor, how the session was established, and where it came from.
- **03 — First moves on the keyboard:** the orientation burst, in order, and the thing inside it that is not the operator at all.
- **04 — Past the role:** enumeration beyond the job, and the material this account had no entitlement to open.
- **05 — Taking it:** staging, compression, and the channel the archive actually left through.
- **06 — Judgement:** what was left behind, where the operator actually sat, and the honest root cause.

**Note on the absence:** two of the closing findings are negatives — no persistence, one machine (not two). When a table expected to be busy comes back quiet, that quiet is data, but only if what's in there can be accounted for. Prove it, don't assume it.

## Final Report Requirements
(Inferred from series convention — confirm against Section 00 gate materials once in the range.)
- Executive summary
- Confirmed scope (host, account, window)
- OSINT findings and how they led to the account/host
- Detailed attack timeline
- Initial access and root cause
- Actions on keyboard / enumeration beyond role
- Data accessed and exfil channel
- Host and account impact
- Dismissed alerts / noise with reasoning (brute-force floor, benign deletions)
- Proven negatives (no persistence, single host)
- Recommended prevention and detection improvements

Clearly separate confirmed facts, reasonable conclusions, and unanswered questions. Every important claim should be tied to telemetry or an analysed artefact.
