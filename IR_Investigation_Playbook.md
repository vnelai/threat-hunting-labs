# IR Investigation Playbook — KQL Threat Hunting

> Built from Mission 02 (Hidden Directive). Not mission-specific, reusable for any future hunt against
> Sentinel + Defender/MDE telemetry. Goal: know what to search and why, in plain English, before writing
> a single line of KQL. Organized around the MITRE ATT&CK kill chain, same phase order as a typical
> incident-report checklist (C01 Recon, C02 Initial Access, C03 Execution, etc.).

---

## Golden rules (learned the hard way this mission)

1. **Never guess a field name.** If you don't have a confirmed schema, don't write the query. Run schema
   discovery first (see below). Guessing field names wastes far more time than checking does.
2. **A schema panel in the UI is not proof.** It can be stale or show a different table than you think.
   The only ground truth is a query that actually runs against the real table.
3. **`getschema` is your first move on any unfamiliar table**, before writing a real query:
   ```kql
   TableName
   | getschema
   | summarize make_list(strcat(ColumnOrdinal, ": ", ColumnName))
   ```
   This collapses the whole schema into one copyable row instead of a paginated grid you have to scroll.
4. **Custom `_CL` tables and native tables use different time-column conventions.** Sentinel-native and
   custom-logged tables (e.g. `WindowsProcess_CL`) use `TimeGenerated`. Native MDE/Defender Advanced
   Hunting tables (e.g. `DeviceProcessEvents`) use `Timestamp`. Check which kind of table you're in.
5. **If a query errors on a column name, that error is itself the schema check.** Don't retry blindly,
   read the exact error text, it tells you the field doesn't exist as written.
6. **A KQL error is progress, not failure.** Every wrong field name ruled out something. Don't take it personally.
7. **Verify a positive with the same rigor as a negative.** Before promoting something to a real finding, pull the underlying command line or process chain and confirm it, don't attribute based on the shape of a known technique alone. A security tool touching a sensitive process shortly after something else happened isn't automatically a deliberate attacker technique, it can be a legitimate, automatic response (e.g. Windows' own crash reporter reacting to memory access that already occurred).
8. **Before flagging anything as attacker persistence, rule out legitimate estate/IT tooling first.** Check the creator, the script path/naming convention, and whether it predates your incident window. A task or service you don't recognize isn't automatically the attacker's, it might just be tooling you haven't seen before.
9. **Before clearing anything as a false positive, confirm your query window actually covers the event's real timestamp.** "Not found in the window I checked" and "didn't happen" are different claims. A cleared finding is far harder to reopen than a question left open, so widen the window before you close the door on something.

---

## Step 0 — Setup, before touching any specific phase

**What we're doing:** figuring out what data actually exists before hunting for anything specific.

- **Scope your hosts/entities.** Get exact hostnames in scope (watch for case-variant duplicates in the
  tenant, e.g. `GF-WS01` vs `gf-ws01`, include both).
- **Table discovery** — find out what tables actually have data for your hosts/window, don't assume:
  ```kql
  search "HOST1" or "HOST2" or "HOST3"
  | where TimeGenerated between (datetime(start) .. datetime(end))
  | summarize Events=count() by Table=$table
  | sort by Events desc
  ```
  Run this in *every* workspace in scope (e.g. Sentinel LAW and the Defender/MDE LAW are often separate
  workspaces with different table sets). Confirms real table names instead of guessing.
- **Confirm timezone.** Check what the query pane displays (UTC+00:00 etc.) for each workspace/portal
  separately, don't assume they match each other.
- **Find the clean, scenario-built alert set if one exists.** Real environments/ranges often have a
  custom-prefixed alert rule set (e.g. everything named "GFD - ...") separate from generic/noisy
  detection rules. Filtering `SecurityAlert` by that prefix beats opening dozens of GUI alerts by hand:
  ```kql
  SecurityAlert
  | where TimeGenerated between (datetime(start) .. datetime(end))
  | where AlertName startswith "PREFIX"
  | project TimeGenerated, AlertName, AlertSeverity
  | sort by TimeGenerated asc
  ```
- **Join native alert tables to get real hostnames + MITRE technique IDs**, instead of trusting alert
  titles alone (e.g. `AlertInfo` joined to `AlertEvidence` on `AlertId`, filtered to `isnotempty(DeviceName)`
  to avoid duplicate/blank-device rows).

---

## The phases

For each phase: what we're actually looking for, in plain English, why it matters, and what "done"
looks like.

### C01 — Reconnaissance
**What:** external scanning/probing before the attacker touched anything internal. Usually invisible to
internal telemetry (it's an outsider's traffic hitting your perimeter, not your endpoints), so this is
often genuinely "not observable" from EDR/SIEM alone unless you have perimeter logs (firewall, WAF).
**Done when:** either a concrete external probing indicator is found, or you can honestly say this phase
sits outside the available telemetry and note it as a limitation, not skip it silently.

### C02 — Resource Development
**What:** infrastructure the attacker built or acquired ahead of time — domains, C2 servers, malware,
phishing kits. You find this by pivoting on IOCs discovered later (a C2 domain's registration date on
VirusTotal, for instance), not by hunting it directly first.
**Done when:** you can name the attacker's infrastructure and roughly when it was stood up, from evidence
(domain age, first-seen timestamps), not assumption.

### C03 — Initial Access
**What:** how the attacker's first code execution happened on the estate. Ask: what's the earliest
malicious event, and what's its immediate parent process/trigger?
**Where to look:** process-creation tables for the earliest anomalous parent→child chain; static analysis
of any recovered artefacts (lure documents, droppers) for their actual mechanism, not just their name.
**Trap to avoid:** don't stop at "a PowerShell download happened", that's Execution evidence, not proof of
*how* PowerShell first got triggered. Keep tracing the parent process chain back one more hop.
**Done when:** you can name the specific delivery mechanism (phishing link, injected instruction, exploit,
valid account) with an artefact or log line to back it, not just a plausible theory.

### C04 — Execution
**What:** the actual code that ran. Static-analyze any recovered scripts/binaries (safely, never execute
them) to describe their real behavior instead of guessing from the filename.
**Where to look:** `WindowsPowerShell_CL`/PowerShell operational logs for script block content; process
tables filtered to the executable in question.
**Done when:** you can describe what the payload actually does, step by step, sourced from the artefact
itself or a command line, not inferred from an alert title alone.

### C05 — Persistence
**What:** every mechanism that survives a reboot/logoff. This is usually the single richest phase because
attackers plant several redundant mechanisms.
**Where to look, systematically, across every host in scope, not just the one you found first:**
- Scheduled tasks: `schtasks`, `New-ScheduledTask`, Security Event ID 4698 (task created, full XML content
  including the actual command in `EventData`).
- Registry Run keys: `reg add`, `CurrentVersion\Run` in command lines.
- Services: `sc stop`/`sc start`/`sc create`, `New-Service`, existing-service binary replacement (stop a
  legitimate service, overwrite its binary, restart it, classic and easy to miss).
- One targeted command-line keyword sweep catches most of this at once:
  ```kql
  WindowsProcess_CL   // or DeviceProcessEvents, Timestamp not TimeGenerated on that table
  | where TimeGenerated between (datetime(start) .. datetime(end))
  | where DvcHostname has_any ("HOST1","HOST2","HOST3")
  | where TargetProcessCommandLine has_any (
      "schtasks","CurrentVersion\\Run","sc stop","sc start","New-ScheduledTask","New-Service","reg add")
  | project TimeGenerated, DvcHostname, ActorUsername, TargetProcessFilePath, TargetProcessCommandLine
  | sort by TimeGenerated asc
  ```
**Trap to avoid:** enumeration looks like planting at a glance. `reg QUERY`/`schtasks /query` is the
attacker *checking* for persistence (Discovery), not creating it. Read the verb, not just the keyword.
**Done when:** every host in scope has been checked with the same method, not just the host where you
found the first mechanism. A host showing nothing is only a finding if you actually looked.

**Don't stop at host-level persistence if a domain controller is in scope.** Scheduled tasks, registry
keys, and services only cover one machine. Also check for domain-wide persistence, which survives even a
full password reset across the estate:
- **AdminSDHolder ACL changes** — grants a permission on a protected account that silently reapplies
  itself on a schedule, so a one-time cleanup doesn't remove it.
- **DCSync-style replication requests** — Security Event 4662 on the domain controller, look for the
  `Get-Changes` / `Get-Changes-All` extended rights granted to an account that shouldn't have them. This
  lets an attacker pull every password hash in the domain without ever touching an individual account
  again.
Both of these are easy to miss because they don't look like "persistence" in the scheduled-task sense,
and skipping them makes an incident's real impact read smaller than it actually was.

### C06 — Privilege Escalation
**What:** how the attacker went from whatever access they started with to a higher privilege level
(user→admin, or admin→SYSTEM). These are two different questions, don't conflate them.
**Where to look:** scheduled tasks/services run as SYSTEM (classic admin→SYSTEM technique); for user→admin,
check whether the account used was newly created or newly promoted:
```kql
SecurityEvent
| where TimeGenerated between (datetime(start) .. datetime(end))
| where Computer has "HOST"
| where EventID in (4720, 4728, 4732, 4756)   // account created / added to group (global, local, universal)
| where TargetUserName has "ACCOUNTNAME" or EventData has "ACCOUNTNAME"
```
A **no-results** answer here is still a real finding: it means the account was already privileged before
the incident, which shifts the open question to Credential Access (how were its creds obtained), not
Privilege Escalation.
**Done when:** you can state which specific technique converted privilege level A to B, and separately
whether the account itself was pre-existing or attacker-created/promoted.

### C07 — Defense Evasion
**What:** anything that blinds or bypasses security tooling. AMSI bypass, AV/EDR disabling, process
injection, disguised/renamed binaries, log clearing.
**Where to look:** artefact static analysis for AMSI-patching code; `Set-MpPreference` calls disabling
Defender; process-injection alerts (T1055 and sub-techniques) cross-referenced to what technique the
artefact actually implements (in-memory execution via VirtualAlloc/CreateThread, for instance).
**Done when:** every evasion technique found has both an alert/telemetry hit AND, where possible, an
artefact-level explanation of the actual mechanism, not just the alert name.

### C08 — Credential Access
**What:** how account credentials got stolen (LSA secrets dumping, credential caching abuse, etc).
**Where to look:** alerts naming LSA secrets/credential theft directly; correlate the account compromised
against where it's first *used* afterward (that tells you the theft happened before that point).
**Done when:** you know which accounts were compromised and can bound the window during which the theft
must have happened (between last-known-clean use and first-malicious-use).

**Check the low-hanging fruit before the noisy stuff.** Attackers usually try cheap/quiet credential
tricks before something loud like LSA dumping. Worth checking these first, and worth noting if they're
absent (skipping straight to hard methods is itself a finding):
```kql
WindowsProcess_CL
| where TimeGenerated between (datetime(a) .. datetime(b))
| where DvcHostname has "HOST"
| where TargetProcessCommandLine has_any (
    "cmdkey",              // saved Credential Manager entries
    "ConsoleHost_history",  // PowerShell command history, sometimes has typed passwords
    "Get-ADUser",           // often paired with Description below
    "Description",          // classic: passwords left in AD user Description field
    "PSReadLine")           // module behind PowerShell history
| project TimeGenerated, ActorUsername, TargetProcessCommandLine
| sort by TimeGenerated asc
// Read the order — quiet methods usually come before noisy ones. Then check which one
// actually produced a usable credential downstream.
```

**If the quiet stuff doesn't pan out (or even if it does), check for LSASS memory access next.** This is
the step up from the low-hanging-fruit check above — `lsass.exe` holds live credentials (hashes, Kerberos
tickets) in memory, and reading it is the classic move behind tools like Mimikatz:
```kql
WindowsProcessAccess_CL   // logs one process opening a handle on another process
| where TimeGenerated between (datetime(a) .. datetime(b))
| where DvcHostname has "HOST"
| where TargetProcessFilePath has "lsass"
| project TimeGenerated, ActorUsername, ActingProcessFilePath, TargetProcessFilePath, GrantedAccess
| sort by TimeGenerated asc
```
What to look for in the result: **`GrantedAccess` of `0x1010`** (`PROCESS_VM_READ` + `PROCESS_QUERY_LIMITED_INFORMATION`)
is a deliberately minimal, quiet access mask, exactly what credential-dumping tools use to avoid detection
rules that only watch for full-access (`PROCESS_ALL_ACCESS`) handles on LSASS. Also check `ActingProcessFilePath`
— if it's something with no legitimate reason to touch LSASS (Explorer, a browser, anything not a security
tool), that's a strong tell, either process injection into that process or a tool masquerading as it.
Cross-check the timestamp against any credentials already found elsewhere (e.g. an account logon shortly
after) to figure out whether this dump is the *source* of a specific credential, or a broader harvest.

### C09 — Discovery
**What:** the attacker mapping the environment: LDAP queries, registry/service enumeration, network scans.
**Trap to avoid:** this phase overlaps heavily with Persistence and Collection in raw command lines
(`reg QUERY` vs `reg ADD`, `schtasks /query` vs `schtasks /create`). Always check the verb.
**Done when:** you can distinguish "attacker learning about the environment" activity from "attacker
changing the environment" activity in your evidence, not just list commands.

### C10 — Lateral Movement
**What:** how the attacker moved host to host. Remote access tools (AnyDesk etc.), WMI/Impacket-style
remote execution, valid account reuse across hosts.
**Where to look:** alerts naming remote-access software directly; process-creation parent chains showing
`WmiPrvSE.exe` (check whether the call was local or remote via network telemetry on port 135/RPC before
assuming remote); repeated use of the same account across multiple hosts in the timeline.
**Done when:** you have a host-to-host chain with timestamps, not just "movement happened somewhere."

### C11 — Collection
**What:** data being gathered/archived pre-exfiltration. `robocopy /MIR`, `7z`/`winrar`, `Compress-Archive`,
recursive `Get-ChildItem`.
**Trap to avoid:** a matched rule doesn't mean the *content* matches the rule's assumed threat model,
check what was actually archived (an OS artifact folder like Prefetch reads very differently than a
user's documents folder, even though the same detection rule fires for both).
**Done when:** you know what was actually staged, not just that a staging *tool* ran.

### C12 — Command and Control
**What:** the ongoing channel back to the attacker. Malware family C2 (confirmed backdoors), recurring
beacon-style network calls, abused remote-access software.
**Done when:** you can name the C2 domain/infrastructure and show the recurring cadence with timestamps.

### C13 — Exfiltration / Impact
**What:** data actually leaving, or destructive/disruptive actions (encryption, deletion, service
disruption). Usually the last alerts in the timeline chronologically, check the tail end of your alert
pull, not just the middle.
**Done when:** you can state what left the network (or that nothing did, with evidence for that too) and
what damage, if any, was done.

**Before writing "no evidence of exfiltration," re-run the check with a wider window than the stated
incident timeframe.** A staging or archive command (`Compress-Archive`, `7z`, `robocopy /MIR`) sitting even
a few minutes outside your query window will silently read as absence, not as a real negative. See Golden
Rule 9, this is the single costliest mistake to get wrong because a cleared finding almost never gets a
second look.

---

## The full-account-timeline TTP (found the most in one shot, worth remembering)

Once you have a suspect account (from any lead — a lateral-movement alert, a shared pivot IP, anything),
stop keyword-filtering and just pull **everything that account ran, full command lines, no filter at
all**. Keyword sweeps only catch what you already thought to search for; an unfiltered timeline catches
what you didn't. This single query pattern surfaced privilege-escalation recon (`AlwaysInstallElevated`,
`whoami /priv`), a second escalation path via SQL Server `xp_cmdshell` abuse, a persistent AnyDesk
backdoor, an attacker-initiated password change, and a second compromised account's plaintext password,
all in one pull, none of which any keyword list would have been guaranteed to catch.

```kql
WindowsProcess_CL
| where TimeGenerated between (datetime(a) .. datetime(b))
| where DvcHostname has_any ("H1","H2","H3")
| where ActorUsername has "SUSPECT_ACCOUNT"
| project TimeGenerated, DvcHostname, TargetProcessFilePath, TargetProcessCommandLine
| sort by TimeGenerated asc
```

How to read the output fast (it'll be long, mostly normal-user noise): scan `TargetProcessFilePath` for
anything that isn't routine desktop software (browsers, Office, Adobe), then read those specific command
lines closely. Things worth stopping on: `whoami`/`whoami /priv` (privilege awareness), `reg query` against
policy keys (misconfiguration checks), `certutil`/`bitsadmin`/`curl` with a URL (LOLBin download), `net
user`/`net use` with a password in plain sight (credential manipulation/reuse), `SQLCMD`/database tools
(lateral movement via an application), any remote-access tool with a `--set-password`-style flag
(persistence via legitimate software), `schtasks`/`sc`/`reg add` (already covered above, persistence).

**When to use this vs. the keyword sweep:** keyword sweep first, across *all* hosts/accounts, to find who
to suspect. Full-timeline pull second, once you have a specific account, to find everything they did.

## Checking a Linux/VPN pivot host

If a shared source IP keeps showing up across multiple compromised Windows accounts but never appears as
its own `DvcHostname` in Windows telemetry, check whether it's a VPN-assigned address by looking at
`LinuxNetwork_CL` (confirmed schema, real column names, no guessing needed):

```kql
LinuxNetwork_CL
| where TimeGenerated between (datetime(a) .. datetime(b))
| where SrcIpAddr == "SUSPECT_IP" or DstIpAddr == "SUSPECT_IP"
| project TimeGenerated, DvcHostname, NetworkDirection, SrcIpAddr, SrcPortNumber, DstIpAddr, DstPortNumber, ActorUsername, ActingProcessName
| sort by TimeGenerated asc
```

If this resolves to a VPN gateway host, check whether the connecting/external side is a public IP —
that's a real External Remote Services (T1133) finding, a different angle on access than an endpoint-based
initial-access story, and worth its own writeup rather than folding into an existing finding.

## Quick-reference: useful KQL shapes

**Collapse a full schema into one copyable line:**
```kql
TableName | getschema | summarize make_list(strcat(ColumnOrdinal, ": ", ColumnName))
```

**Table discovery across a workspace:**
```kql
search "HOST1" or "HOST2" | where TimeGenerated between (datetime(a) .. datetime(b))
| summarize Events=count() by Table=$table | sort by Events desc
```

**Per-host event counts (answers "which host actually has data here"):**
```kql
TableName | where TimeGenerated between (datetime(a) .. datetime(b))
| where DeviceName has_any ("H1","H2","H3") | summarize count() by DeviceName
```

**Join alert-detail to alert-entity tables to get real hostnames on generic alert titles:**
```kql
AlertInfo
| where TimeGenerated between (datetime(a) .. datetime(b))
| project AlertId, TimeGenerated, Title, Category, AttackTechniques
| join kind=inner (AlertEvidence | where isnotempty(DeviceName) | project AlertId, DeviceName) on AlertId
| distinct TimeGenerated, DeviceName, Title, Category, AttackTechniques
| sort by TimeGenerated asc
```

**Command-line keyword sweep (the persistence/execution workhorse — this exact query cracked Mission 02's
persistence AND fed directly into privilege escalation, worth remembering):**
```kql
WindowsProcess_CL | where TimeGenerated between (datetime(a) .. datetime(b))
| where DvcHostname has_any ("H1","H2","H3")
| where TargetProcessCommandLine has_any ("keyword1","keyword2",...)
| project TimeGenerated, DvcHostname, ActorUsername, TargetProcessFilePath, TargetProcessCommandLine
| sort by TimeGenerated asc
```

**Was this account created/promoted during the window (privilege escalation check):**
```kql
SecurityEvent | where TimeGenerated between (datetime(a) .. datetime(b))
| where Computer has "HOST" | where EventID in (4720, 4728, 4732, 4756)
| where TargetUserName has "ACCOUNT" or EventData has "ACCOUNT"
```
