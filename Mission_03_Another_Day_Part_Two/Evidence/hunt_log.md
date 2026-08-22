# Hunt Log — Mission 03: Another Day, Part Two

Running log of steps taken and lessons learned during the hunt. Not the final report — raw working notes.

---

### Step 1 — Scoping filters (host + date range)
**Q:** How to filter KQL by machine name and date range.
**A:**
```kql
TableName
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-31))
```
- Use `startswith`, not `==` — device is registered under its FQDN (e.g. `nh-wks-it-01.nimbushealth.local`), so exact match will silently return nothing.
- Date range is end-exclusive-friendly if you use `31` as the upper bound to cover all of the 30th — safer than `datetime(2026-05-30)` which cuts off at midnight.
- Native MDE tables use `Timestamp`; Sentinel-native/custom `_CL` tables use `TimeGenerated` — check which one you're in.

**Lesson:** Always bind host + date filters together on every query in this hunt — shared workspace, results outside the window belong to a different case (March = part one).

### Step 2 — Third filter: the account
Brief calls out **three** ways to lose yourself in this shared workspace, not two: date window, host, **and account**. Missing the account filter on a shared box pulls in every other user's activity too.

```kql
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-31))
| where AccountName =~ "the_username"
```

**`==` vs `startswith`:**
- `==` requires an exact full-string match. Device is registered under its FQDN (e.g. `nh-wks-it-01.nimbushealth.local`), so `DeviceName == "nh-wks-it-01"` compares the short name against the full domain name and returns nothing.
- `startswith` matches on a prefix, so it catches the FQDN regardless of what's appended.

**Lesson:** Three filters, not two — host, date, account — bound on every query. An exact-match (`==`) on a short hostname silently returns zero rows when the field actually holds an FQDN; always confirm the real stored value with `| take 1` or `getschema` before assuming `==` is safe.

---

### Q00 — Setup Gate
**Gate phrase:** "Nimbus support review ready" — stated directly in the brief text.

### Q01 — The account under review
Not yet identified. Mission 03 is a separate incident from Mission 01 (March, billing analyst) — no dependency between them.

**Evidence bag received (4 artefacts, none from SIEM):**
- **Artefact 01 — Public Professional Profile:** link only, content not yet pulled.
- **Artefact 02 — Breach Exposure Report:** link only, content not yet pulled. Note from the bag: don't stop at the breach count — check *what* leaked and *how old* each breach is; not all exposed data is equally useful for a login attempt today.
- **Artefact 03 — Cached Support Reference (full text captured):** internal Nimbus IT doc, cached 30 Apr 2026, used during the May staffing expansion to point new IT/MSP staff to approved remote-support systems.
  - System: `NH-WKS-IT-01`
  - Purpose: IT administration and support workstation
  - Public address: `135.237.163.62`
  - Internal address: `10.1.0.233`
  - Notes: use domain credentials when prompted; access reviews performed periodically by Nimbus IT + Log(N) Pacific.
  - **Confirms:** this host was intentionally publicly documented as a remote-support endpoint — a plausible reason an outsider would target it specifically.
- **Artefact 04 — Role Matrix & Environment:** link only, content not yet pulled. This is the yardstick for what's in-role vs. out-of-role later (Phase 04).

**Still needed:** the employee's name/username — expected from Artefact 01 (profile) cross-referenced with Artefact 04 (role matrix, recent hires).

**Lesson:** The cached support doc is itself an exposure — an internal remote-access reference (hostname + public IP) leaked into a public document cache. That's a second, independent way this host became a target, separate from the credential-reuse angle.

**Artefact 01 — Public Professional Profile — read as an attacker (note: image didn't actually transfer, analysis captured from description only):**
- Employer named on the profile → confirms Nimbus Health as the company being targeted, not a random individual.
- Role: IT support technician.
- Tenure: ~1 month (brand new hire) → still learning, plausible easier target (less trained on security hygiene, less scrutiny yet).
- IT support role = access to endpoints and shared workstations → lateral movement potential baked into the job itself.
- Bio line: handles account access requests and coordinates password resets → high-value for initial access; this person is close to the credential/provisioning process.
- Also installs software → another avenue of legitimate-looking access/execution.
- Profile mentions rising patient volume → environment under operational strain (ties back to the brief's "growth first, access review later" framing).
- **Personal email listed on profile: Hotmail address** — this is the pivot to Artefact 02 (breach exposure lookup runs against this personal address, not a corporate one).

**Still needed:** the actual name/username string as it appears in the logs — not yet captured from this artefact.

**Lesson:** A personal contact email published on a public profile is the bridge between OSINT and credential exposure — it's the exact input Artefact 02's breach lookup was run against. Also: new-hire tenure + a job description that explicitly includes password resets is a stronger "why him" signal than "IT support" alone.

**Artefact 01 — confirmed from image (`Mason_Reed_Linkedin_Profile.png`):**
- **Name: Mason Reed**
- Title: IT Support Technician, Nimbus Health, Apr 2026–Present (1 mo tenure)
- About: "supporting Windows endpoints, user account issues, shared workstations, and basic Active Directory workflows... period of growth tied to increased patient volume."
- Experience bullets: first-line support for Billing/Clinical/HR/IT workstations; handles account access requests and coordinates password resets; troubleshoots shared workstations; assists onboarding incl. user setup and software installs.
- Prior role: Help Desk Associate, Northline Business Services, Aug 2023–Apr 2026.
- Skills: Windows Support, Active Directory Basics, Password Resets, Remote Troubleshooting, Shared Workstation Support, MS365 Support, Help Desk Ticketing, Endpoint Troubleshooting.
- **Public contact email: `mason.reed@hotmail.com`** — this is the input for Artefact 02's breach lookup.
- Recent activity post (public, ~10h old at capture): announces starting the new role, names the clinic's growth and the nearby industrial park opening — same detail as the Hunt Lead brief, so this post itself is plausible OSINT the attacker read directly.

**Working account name for KQL:** not yet confirmed in logs — profile gives `mason.reed` / `m.reed` as likely candidates. **Next action:** `DeviceLogonEvents | where DeviceName startswith "nh-wks-it-01" | take 10` to confirm actual `AccountName` format before filtering.

**Lesson:** The subject's own recent-activity post independently corroborates internal details from the Hunt Lead brief (industrial park, patient volume growth) — a good example of a public post inadvertently confirming/leaking operational context, separate from the profile fields themselves.

**Artefact 02 — Breach Exposure Report (HaveIBeenPwned lookup, `mason.reed@hotmail.com`) — 3 breaches, confirmed from PDF:**
1. **Synthient Credential Stuffing Threat Data — Apr 2025.** Aggregated 2B emails / 1.3B unique passwords from credential-stuffing lists across malicious sources during 2025. Compromised: email + password. **Most recent, plaintext passwords.**
2. **Combolists Posted to Telegram — May 2024.** 2B rows / 361M unique emails from malicious Telegram channels, sourced from existing combolists + infostealer malware. Compromised: email + username + password.
3. **MySpace — breach ~2008, disclosed 2016.** ~360M accounts. Compromised: email + username + password (SHA1 hash of first 10 chars, lowercased, unsalted). **Oldest, and hashed** — crackable but an 18-year-old password, low odds it's still in use.

**Reasoning (per brief's own instruction — don't stop at count, weigh age/format):** The MySpace record is not the useful one here — too old, hashed, near-certainly rotated since. The Synthient set (Apr 2025) is the strongest candidate for "still-valid password" — most recent, plaintext, closest to the May 2026 incident window. Working theory: attacker pulled a password for this email from the Synthient/Telegram exposure and tried it against Mason's Nimbus domain account (classic credential-reuse — same password across personal + work).

**Lesson:** "3 breaches" is not 3 equally useful leads. Age + data format (plaintext vs. hashed) determines which breach could plausibly still hand over a working password today — that's the actual analytic step here, not just noting the count.

**Artefact 03 — Cached Support Reference — plain-language recap:**
Internal Nimbus IT page (`nimbushealth.internal/it/support/remote-support-reference`) was reachable on the open internet at some point, without proper access control. A crawler/caching service picked it up while it was live and stored a snapshot. Nimbus later took the real page down, but the cached copy persisted and stayed publicly readable — the takedown didn't remove the cache. Content: names `NH-WKS-IT-01` as the approved remote-support endpoint, gives its public IP, and its own notes explicitly say to use domain credentials when logging in remotely. So an outside reader gets host + public IP + "yes, normal domain login works here" straight from the leaked doc — no guessing required.

**Lesson:** "Internal" access control means nothing if the page was ever reachable without auth — even a brief exposure window is enough to get cached, and the cache outlives the takedown. This is the "how" behind why `NH-WKS-IT-01` specifically (not some other Nimbus host) was the one worth pointing a stolen credential at.

**Artefact 04 — Role Matrix & Environment (2026-05-01, Nimbus IT → Log(N) Pacific MSP):**

**Q01 answer confirmed — account under review: `m.reed`**
- Role: IT Support Technician, Full-Time, IT dept.
- Start: 2026-04-28 ("New hire added to reduce endpoint support backlog")
- Account Status: Active
- **System Access: IT workstation, IT share, limited workstation support**
- **Privilege Level: Standard User** (not Administrator — that's `l.rodriguez`, IT Administrator, all workstations/servers/all shares)

**Yardstick for "out of role" (Phase 04 later):** m.reed's entitlement stops at the IT workstation/share and "limited workstation support." Billing, HR, and Clinical shares/workstations belong to other departments entirely — any access into `\\NH-FS-01\Billing`, `\HR`, or `\Clinical`, or onto `NH-WKS-BILL-01` / `NH-WKS-HR-01` / `NH-WKS-CLIN-01`, is outside his role by definition.

**Other accounts worth knowing for later phases:**
- `svc_backup` — Service Account, File server backup operations only.
- `NH-Admin` — built-in Domain Administrator, all workstations/servers/all shares.
- `l.rodriguez` — IT Administrator (Infrastructure Lead), full access — the legitimate admin baseline to compare any privilege-escalation attempt against.

**Environment reference:**
- Domain: `corp.nimbushealth.com`, NetBIOS `NIMBUS`
- `NH-DC-01` (Domain Controller) — 20.81.227.17 / 10.1.0.235
- `NH-FS-01` (File Server) — 20.49.48.128 / 10.1.0.234
- `NH-WKS-IT-01` (IT Admin workstation, scope of this hunt) — 135.237.163.62 / 10.1.0.233 — **matches Artefact 03 exactly**
- Other workstations (out of scope but useful context): `NH-WKS-BILL-01`, `NH-WKS-CLIN-01`, `NH-WKS-HR-01`
- Shares: `\\NH-FS-01\Billing`, `\Clinical`, `\HR`, `\IT`

**Lesson:** Artefact 04 corroborates Artefact 03's IP for `NH-WKS-IT-01` — two independent sources agreeing on the same host/IP is a solid confirmation before scoping telemetry. Also: "IT Support Technician" sounds broad, but the matrix pins his actual entitlement down to just the IT workstation/share — narrow enough that almost any lateral reach becomes provable abuse rather than a judgment call.

---

## Flags / Answers Submitted (running tracker)

| # | Question | Answer submitted |
|---|---|---|
| Q00 | Setup gate phrase | "Nimbus support review ready" |
| Q01 | Account under review | `m.reed` |
| — | Which breach can't hand a working password today; which explains credential reuse | MySpace — too old, hashed fragment, unusable. Synthient Credential Stuffing Threat Data — recent, plaintext password, built for password-reuse attacks. |
| — | Public IP an attacker would target (cached support reference) | `135.237.163.62` |
| — | Source IP of the low-volume, targeted, eventually-successful brute force | `116.45.242.115` ✅ correct |
| Q07 | Logon type of the successful logon (not somebody at the desk) | `RemoteInteractive` ✅ correct |
| Q08 | Second external source used shortly after the first session | `45.131.194.61` ✅ correct |
| Q09 | Orientation burst, in order | `whoami, hostname, ipconfig /all, whoami /groups` ✅ correct |
| Q10 | The OneDriveSetup.exe deletion — actor or machine? | Not the operator — OneDrive's own auto-update/startup cleanup process |
| — | Command that asks a specific server what it's sharing | `net view \\NH-FS-01` ✅ correct |
| — | Command enumerating the HR group (out-of-role reach) | `net group "NH-HR-Users" /domain` ✅ correct |
| Q13 | Out-of-role file opened, belonging to another department | `access_request_queue_20260526.csv` ✅ correct (proven via ShellLinkWorkingDirectory `\\Nh-fs-01\hr\2026-05\AccessRequests`) |
| Q14 | Folder where staged material was gathered before compression | `C:\Users\m.reed\Documents\SupportReview` ✅ correct |
| — | Archive filename | `support_review_202605.zip` ✅ correct |
| — | Destination path the archive was written to (over the RDP session, not network) | `\\tsclient\G\Temp\NimbusSupport` |
| Q17 | Persistence established? What are the entries found? | No persistence established; entries are routine Windows Task Scheduler (SYSTEM) tasks, unrelated to the operator |
| — | Did the account run anything on the file server? How was HR data reached instead? | No — reached via SMB network file-share access (`Network`-type logon) from his own workstation ✅ correct |
| Q19 | The honest read — root cause | "External account takeover via RDP from two outside IPs — no malware, no persistence, no insider signs." ✅ correct |
| Q20 | The guessing pattern — credential reuse vs. brute force | "3 failed logons, then success, from `116.45.242.115` in ~2 minutes — matches the Synthient-breach password, not a spray." ✅ correct |
| Q21 | The session switch — the 10-min gap | New `RemoteInteractive` logon from `45.131.194.61` at **1:40:59.113 AM** — a different source IP started a fresh session. ✅ correct |
| Q22 | The channel check — premeditated exfil proof | `net  view \\tsclient` (1:56:12.371 AM) ✅ correct |
| IR1 | First containment action | Disable `m.reed` + isolate `nh-wks-it-01` — reset alone doesn't kill an active session or undo the compromise. ✅ correct |
| IR2 | The disclosure question | `employee_record_EMP-87291_20260527.txt` = employee PII → triggers a data breach notification obligation. ✅ correct |

(Table will keep growing — mission had more than 19 flags after all.)

---

### Step 3 — Confirming DeviceLogonEvents schema, then real filtered pull
**First attempt (unfiltered `take 5`):** returned unrelated data — `linux-target-1` / `root` (cron logons) and `administrator` (LogonFailed) — dated Aug 2026, not the May incident window. **Confirmed lesson from brief:** shared workspace noise, someone else's scenario, not filtered by device/account/time. Did confirm `ActionType` field really does use literal values `LogonSuccess` / `LogonFailed`.

**Corrected query, properly scoped:**
```kql
DeviceLogonEvents
| where DeviceName startswith "nh-wks-it-01"
| where AccountName =~ "m.reed"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-31))
| take 10
```
**Results:** screenshot to be added to `screenshots/` in the project folder — will pull in once dropped.

**Lesson:** Running a query without the full filter set — even just to sanity-check a field — pulls in whatever's most recent across the entire shared table, not your scenario. Always apply device + account + time filters before trusting any result, even a quick schema check.

**Results (screenshot: `screenshots/nh-wks-it-01-mreed-logonevents-take10.png`):** properly scoped query returned 10 rows, all `m.reed` on `nimbus` domain, all `ActionType: LogonSuccess` / `LogonAttempted`, all `"IsLocalLogon":true`. Times: 5/26 11:40:01 PM, 5/27 1:40:01 AM, 5/27 1:40:25 AM, 5/27 5:40:25 AM (paired Success+Attempted rows each time).

**Read:** these are local console logons, not remote. Recurring every ~2 hrs — plausible normal/benign activity (or a scheduled task), not the external brute-force attempt. `RemoteIP` column wasn't visible/populated in this pull — need to explicitly filter for it.

**Next query — isolate remote logons with a source IP:**
```kql
DeviceLogonEvents
| where DeviceName startswith "nh-wks-it-01"
| where AccountName =~ "m.reed"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-31))
| where isnotempty(RemoteIP)
| project Timestamp, ActionType, RemoteIP, RemoteIPType, LogonType
```

**Lesson:** `take N` with no `order by` and no extra filter just grabs *some* rows meeting the where-clauses — not necessarily the interesting ones. Local vs. remote logons are a different signal entirely (`IsLocalLogon` flag) — don't assume the first batch returned is the attack; check what's actually in `AdditionalFields`/`RemoteIP` before concluding.

### Step 4 — ActionType breakdown, then isolating the real remote source

**Full ActionType count for `m.reed` on `nh-wks-it-01`, May window (screenshot: `nh-wks-it-01-mreed-actiontype-summary.png`):**
| ActionType | Count |
|---|---|
| LogonAttempted | 55 |
| LogonSuccess | 89 |
| LogonFailed | **3** |

Only 3 failed logons against this account specifically — confirms the brief's description exactly ("low volume, patient, eventually succeeds"), and confirms per-account filtering is what cuts through the "dozens of sources, thousands of failures" noise (that volume is hitting generic accounts like `administrator`, not `m.reed`).

**Query used to isolate remote/network logons with source IP (screenshot: `nh-wks-it-01-mreed-remoteip-network-events.png`):**
```kql
DeviceLogonEvents
| where DeviceName startswith "nh-wks-it-01"
| where AccountName =~ "m.reed"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-31))
| where ActionType in ("LogonFailed", "LogonSuccess")
| where isnotempty(RemoteIP)
| project Timestamp, ActionType, RemoteIP, RemoteIPType, LogonType
| order by Timestamp asc
```

**Results:**
| Timestamp (UTC) | ActionType | RemoteIP | Type | LogonType |
|---|---|---|---|---|
| 5/29 1:26:21.410 AM | LogonFailed | 116.45.242.115 | Public | Network |
| 5/29 1:27:14.279 AM | LogonFailed | 116.45.242.115 | Public | Network |
| 5/29 1:27:52.321 AM | LogonFailed | 116.45.242.115 | Public | Network |
| 5/29 1:28:22.212 AM | LogonSuccess | 116.45.242.115 | Public | Network |
| 5/29 1:28:23.378 AM | LogonSuccess | 116.45.242.115 | Public | Network |
| 5/29 1:28:27.660 AM | **LogonSuccess** | **116.45.242.115** | Public | **RemoteInteractive** |
| 5/29 1:28:43.372 AM | LogonSuccess | 45.131.194.61 | Public | Network |
| 5/29 1:40:53.753 AM | LogonSuccess | 45.131.194.61 | Public | Network |
| 5/29 1:40:55.020 AM | LogonSuccess | 45.131.194.61 | Public | Network |
| 5/29 1:40:59.113 AM | **LogonSuccess** | **45.131.194.61** | Public | **RemoteInteractive** |
| 5/29 1:47:23.812 AM | LogonSuccess | ::1 | Loopback | CachedInteractive |

**FLAG ANSWERED — source IP for the account-specific brute-force success: `116.45.242.115`** ✅ confirmed correct.

Pattern: 3 failed guesses → 2 `Network`-type successes → 1 `RemoteInteractive` success, all `116.45.242.115`, all within ~2 minutes (1:26:21–1:28:27 AM). That final `RemoteInteractive` at 1:28:27 AM is the actual interactive session establishment — the moment someone was "on the keyboard," not just authenticating.

**Flagged for later phases — do not conclude yet:** a **second public IP, `45.131.194.61`**, shows up just 16 seconds after the first RemoteInteractive success, with its own `Network` successes and its own `RemoteInteractive` session 12 minutes later (1:40:59 AM) — and with **zero failed attempts** of its own. That's a different pattern from the brute-forcer (walks straight in, no guessing). Worth carrying into Phase 06 ("where the operator actually sat") — possibilities include a pivot/relay, a second attacker-controlled address, or the "real" operator's IP versus a scanning/testing source. Not concluding cause yet — needs more evidence (process/command-line activity tied to each session) before calling it either way.

The `::1` (loopback) `CachedInteractive` entry at 1:47:23 AM is a normal Windows artifact (local session caching), not a remote indicator — noted per the brief's "not every deletion/artifact is a cover-up, learn to tell a machine apart from a person" guidance.

**Lesson:** Don't stop at the first successful remote IP just because it matches the flag's description. A second IP appearing in the same tight timeframe with a cleaner (no-failure) success pattern is exactly the kind of detail that's easy to skim past — flag it now, resolve it later with more evidence rather than guessing which one "the operator" really was.

**RemoteInteractive session timestamps (the two actual interactive logons — anchor points for "on the keyboard"):**
- **116.45.242.115** → `RemoteInteractive` at **5/29/2026, 1:28:27.660 AM UTC**
- **45.131.194.61** → `RemoteInteractive` at **5/29/2026, 1:40:59.113 AM UTC**
- Gap between the two interactive sessions: ~12 min 31 sec.

### Reference — Process names worth recognizing (general, not mission-specific)

**Session/profile housekeeping (benign, fires automatically on any logon):**
`TSTheme.exe`, `rdpclip.exe`, `sihost.exe`, `taskhostw.exe`, `ctfmon.exe`, `userinit.exe`, `dllhost.exe`, `SearchProtocolHost.exe`, `unregmp2.exe` (esp. `/FirstLogon`), `ie4uinit.exe`, `smartscreen.exe`.

**Discovery/recon built-ins (operator getting their bearings):**
`whoami.exe`, `hostname.exe`, `systeminfo.exe`, `net.exe` (`net user`, `net localgroup administrators`, `net group`, `net use`), `nltest.exe`, `quser.exe`/`query.exe`, `tasklist.exe`, `ipconfig.exe`, `ping.exe`, `nslookup.exe`.

**Execution/scripting hosts (legit tools, also common LOLBins):**
`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `wmic.exe`, `rundll32.exe`, `regsvr32.exe`.

**Persistence:** `schtasks.exe`, `sc.exe`, `reg.exe`, `at.exe`.

**Credential access:** `procdump.exe`, `WerFault.exe`, `rundll32.exe` + `comsvcs.dll` (LSASS dump pattern), `ntdsutil.exe`.

**Collection/staging/exfil:** `robocopy.exe`, `xcopy.exe`, `7z.exe`/compress utils, `makecab.exe`, `certutil.exe`, `bitsadmin.exe`, `curl.exe`.

**Key lesson:** `FileName` alone rarely proves anything (`net.exe` is used constantly for legitimate reasons). It's the combination of `ProcessCommandLine` (switches/targets) + `InitiatingProcessFileName` (what launched it — e.g. `cmd.exe`/`powershell.exe` right after a compromised-account logon, vs. `svchost.exe`/`winlogon.exe` doing normal OS housekeeping) that turns a plain binary into evidence.

### KQL technique note — paging through results without gaps
```kql
... | order by Timestamp asc | serialize rn = row_number() | where rn between (16 .. 45)
```
`serialize` locks in row order after `order by` (KQL doesn't guarantee order downstream otherwise). `row_number()` then numbers rows sequentially in that locked order — only works after `serialize`. Use this to page through large result sets (e.g. 221 rows) in fixed batches with zero gap or overlap, instead of guessing a new time window and risking skipping the actual event of interest.

### Step 5 — Cutting through 221 rows: filter to known recon binaries instead of paging blindly

Paging rn 1–15, 16–45 still landed entirely in Edge/Windows first-run noise (Edge installer `setup.exe`, `msedge.exe` crashpad/GPU/utility/renderer processes, `RunDll32` cache migration, duplicate `unregmp2.exe /FirstLogon`) — all still automatic, not operator, timestamps 1:28:29–1:28:47 AM.

**Switched approach — filter `FileName` to the recon/discovery binary list instead of paging sequentially:**
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-wks-it-01"
| where AccountName =~ "m.reed"
| where Timestamp between (datetime(2026-05-29 01:28:00) .. datetime(2026-05-29 02:00:00))
| where FileName in~ ("whoami.exe","hostname.exe","systeminfo.exe","net.exe","net1.exe","nltest.exe","quser.exe","query.exe","tasklist.exe","ipconfig.exe","ping.exe","nslookup.exe","cmd.exe","powershell.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

**Results (`query_data.csv`, screenshot `nh-wks-it-01-mreed-first-burst-filtered.png`) — TWO distinct bursts found, tied to the two separate RemoteInteractive sessions:**

**Burst 1 — "getting bearings" (tied to 116.45.242.115's session, opened 1:28:27 AM):**
| Time (UTC) | FileName | ProcessCommandLine | Initiator |
|---|---|---|---|
| 1:30:09.079 | cmd.exe | `"cmd.exe"` | explorer.exe |
| 1:30:14.835 | whoami.exe | `whoami` | cmd.exe |
| 1:30:20.787 | HOSTNAME.EXE | `hostname` | cmd.exe |
| 1:30:39.532 | ipconfig.exe | `ipconfig  /all` | cmd.exe |
| 1:31:04.254 | whoami.exe | `whoami  /groups` | cmd.exe |

Shell opened 1m42s after logon (1:28:27→1:30:09) — matches the question's "session opens a couple of minutes before the first real command" hint exactly.

**FLAG ANSWERED — Q09, the orientation burst, in order:** `whoami, hostname, ipconfig /all, whoami /groups` (raw log records these with a double space between command and switch, e.g. `"ipconfig  /all"` — try single-space first, fall back to literal double-space if rejected).

**Burst 2 — deeper enumeration (tied to 45.131.194.61's session, opened 1:40:59 AM) — NOT part of Q09, flagged for Phase 04 ("past the role"):**
| Time (UTC) | FileName | ProcessCommandLine | Initiator |
|---|---|---|---|
| 1:41:12.897 | cmd.exe | `"cmd.exe"` | explorer.exe |
| 1:41:16.107 | net.exe | `net  view` | cmd.exe |
| 1:41:16.400 | cmd.exe | `del /q "...\OneDrive\Update\OneDriveSetup.exe"` | explorer.exe |
| 1:41:16.446 | cmd.exe | `del /q "...\OneDrive\StandaloneUpdater\OneDriveSetup.exe"` | explorer.exe |
| 1:41:40.276 | net.exe | `net  view` | cmd.exe |
| 1:43:19.948 | net.exe | `net  view \\NH-FS-01` | cmd.exe |
| 1:44:05.382 | net.exe | `net  user/domain` | cmd.exe |
| 1:44:31.297 | net.exe | `net  user` | cmd.exe |
| 1:44:39.729 | net.exe | `net  user /domain` | cmd.exe |
| 1:45:34.380 | net.exe | `net  group /domain` | cmd.exe |
| 1:46:23.581 | net.exe | `net  group "NH-HR-Users" /domain` | cmd.exe |
| 1:55:20.545 | powershell.exe | `"powershell.exe"` | explorer.exe |
| 1:56:12.371 | net.exe | `net  view \\tsclient` | cmd.exe |

**Reasoning — two behaviorally distinct sessions, same account:** Session 1 (116.45.242.115) ran a short, generic 4-command "who/what am I" check — the shape of someone confirming they're in. Session 2 (45.131.194.61), ~10 min later, ran a much deeper enumeration: file server (`NH-FS-01`) share discovery, domain user/group enumeration, and specifically queried the **`NH-HR-Users`** group by name — m.reed is IT Support (per Artefact 04's role matrix: IT workstation/share only), so probing an HR-specific AD group is clearly outside his role. Also deleted two OneDrive updater files (housekeeping or anti-detection — not yet determined). This strengthens the earlier flagged theory that the two IPs may represent different roles/stages (light validation vs. the actual working session) rather than the same behavior twice — still not concluding cause, just noting the pattern is now evidenced, not assumed.

**Lesson:** When paging sequentially through hundreds of noise rows gets slow, pivot to filtering by known-relevant `FileName` values — it can jump straight past irrelevant housekeeping and land on exactly the rows that matter, as long as the filter list is broad enough not to miss anything (still worth spot-checking surrounding rows once the burst is found, in case something relevant used an unlisted binary).

### Step 6 — Q10: the OneDriveSetup.exe deletion — actor or machine?

**Zoomed, unfiltered query around 1:41:16 AM:**
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-wks-it-01"
| where AccountName =~ "m.reed"
| where Timestamp between (datetime(2026-05-29 01:41:10) .. datetime(2026-05-29 01:41:20))
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Key rows:**
| Time | FileName | Command | Initiator |
|---|---|---|---|
| 1:41:14.982 | OneDrive.exe | `"OneDrive.exe" /background` | explorer.exe |
| 1:41:16.107 | net.exe | `net  view` | cmd.exe (operator's shell) |
| 1:41:16.400 | cmd.exe | `"cmd.exe" /q /c del /q "...\OneDrive\Update\OneDriveSetup.exe"` | explorer.exe |
| 1:41:16.446 | cmd.exe | `"cmd.exe" /q /c del /q "...\OneDrive\StandaloneUpdater\OneDriveSetup.exe"` | explorer.exe |

**Reasoning:** `OneDrive.exe /background` auto-launches 1.4 seconds before the deletions — this is OneDrive's normal auto-start behavior at session logon. The two delete commands are each a self-contained `cmd.exe /q /c` one-shot invocation (run one command, exit), fired 46ms apart — no human types two full paths that fast — and both are initiated by `explorer.exe`, not by the operator's actual interactive shell (which is busy running `net view` in a separate lineage). Same startup chain as OneDrive itself, immediately after it launches: this is OneDrive cleaning up its own leftover installer files, not the operator "tidying up."

**FLAG ANSWERED — Q10:** Not the operator — OneDrive's own auto-update/startup cleanup process deleting its leftover installer files.

**Lesson:** Timing proximity to operator activity isn't causation. The deletion sat inside the same burst window as `net view`, but process lineage (`InitiatingProcessFileName`/`InitiatingProcessCommandLine`) shows it's a completely separate chain triggered by OneDrive's own startup, not typed by the person in the shell. This is the exact "not every deletion is a cover-up — learn to tell a machine from a person" lesson from the brief, now evidenced rather than assumed.

### Step 7 — Q13: file access outside the IT share (in progress) + a side finding

**Table/field troubleshooting hit multiple dead ends before landing:**
1. `DeviceFileEvents` on `nh-wks-it-01` with `InitiatingProcessAccountName` + `FolderPath has "NH-FS-01"` → empty. **Reason:** file events log on the device where the file lives, not the requesting device — need to scope to `nh-fs-01` instead.
2. `DeviceFileEvents` on `nh-fs-01` with `InitiatingProcessAccountName` → empty. **Reason:** wrong field — network/SMB access to a file server has no local initiating process, so this field is blank. Confirmed via `getschema`: the correct field is `RequestAccountName` (also `RequestAccountDomain`, `RequestAccountSid`, `ShareName`, `RequestSourceIP`).
3. `RequestAccountName =~ "m.reed"` narrowed to 1:40-2:00 AM on `nh-fs-01` → empty, even though the same filter against the full May window correctly returned his **normal IT-share work** (`\Shares\IT\...` — build notes, ticket notes, vendor docs, system checks — routine daily activity on 5/25 and 5/28, all in-role, not the incident).
4. Suspected `Timestamp` vs `TimeGenerated` field mismatch — testing without account filter showed `TimeGenerated` returns rows in the 1:49 AM window that `Timestamp` did not, in at least one query. **Not fully resolved** — re-tests were inconsistent, worth re-verifying which field is actually reliable on this table before drawing a firm conclusion.
5. Anchored the search window to what's already proven from process telemetry instead of guessing: `net view \\NH-FS-01` at 1:43:19.948 AM, `net group "NH-HR-Users" /domain` at 1:46:23.581 AM → real window is ~1:43–1:56 AM, not the full day.

**Side finding surfaced while troubleshooting — worth its own thread:** unfiltered `DeviceFileEvents` on `nh-fs-01`, 1:43–1:57 AM, turned up:
- `__PSScriptPolicyTest_*.ps1`/`.psm1` files (SYSTEM, `C:\Windows\SystemTemp\`) — **benign**, PowerShell auto-generates one of these on every script invocation as a policy check artifact.
- **`f44kmtfh` (folder) + `f44kmtfh.dll`**, SYSTEM, `C:\Windows\SystemTemp\`, created **1:49:25.646–1:49:38.096 AM** — a randomly-named folder+DLL pair is the classic signature of PowerShell's `Add-Type` compiling inline C# on the fly. Legitimate PowerShell behavior, but also a known technique for loading custom/unmanaged code, sometimes abused for in-memory payloads. Timing sits *before* the interactive `powershell.exe` window opens at 1:55:20 AM under the operator's session — meaning something was compiling code under SYSTEM context earlier and separately.
- **RESOLVED — benign.** `DeviceProcessEvents` on `nh-fs-01`, 1:49:20–1:49:45, shows the full chain: `SenseIR.exe` ("OfflineSenseIR" Live Response mode) launches a **signed** PowerShell script (`-ExecutionPolicy AllSigned`) from `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\...` → that script invokes `csc.exe`/`cvtres.exe` to compile the `f44kmtfh` helper DLL. `SenseIR.exe` is Microsoft Defender ATP's own Live Response/data-collection engine — this is the EDR agent running its own signed diagnostic tooling, not attacker activity. Second confirmed instance of the brief's "not every deletion/artifact is a cover-up — check who's actually behind it" lesson, this time for a compiled-code artifact rather than a deletion.

**Q13 RESOLVED.** Root cause of the empty results: filtering by `FolderPath has "NH-FS-01"` on the workstation side assumed a UNC-path access pattern; dropping that assumption and pulling everything `m.reed` touched locally in the 1:43–1:57 AM window surfaced it directly.

**Winning query:**
```kql
DeviceFileEvents
| where DeviceName startswith "nh-wks-it-01"
| where InitiatingProcessAccountName =~ "m.reed"
| where TimeGenerated between (datetime(2026-05-29 01:43:00) .. datetime(2026-05-29 01:57:00))
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

**CORRECTED — `employee_record_EMP-87291_20260527.txt` was rejected as the flag answer.** No `.lnk`/ShellLink evidence exists for it, so its origin path was never actually confirmed — it may have been typed/generated locally rather than opened from a network share. Still real, still worth keeping in the report, just not proven to have crossed a share boundary.

**Real proof came from `DeviceEvents`, `ActionType == "ShellLinkCreateFileEvent"`** — Windows creates a `.lnk` shortcut in `Recent` whenever a file is opened via Explorer, and its `AdditionalFields.ShellLinkWorkingDirectory` records the **actual original network path** the file was opened from:

| .lnk | ShellLinkWorkingDirectory | Share |
|---|---|---|
| `workstation_build_notes_20260528.lnk` | `\\Nh-fs-01\it\2026-05\WorkstationBuilds` | IT — in-role |
| `support_ticket_notes_20260528.lnk` | `\\Nh-fs-01\it\2026-05\SupportTickets` | IT — in-role |
| `access_request_queue_20260526.csv.lnk` | **`\\Nh-fs-01\hr\2026-05\AccessRequests`** | **HR — out of role** |

Even though "access requests" sounds IT-adjacent by content, the file physically lives on the **HR share**, not IT — and the role matrix entitles him to the IT share only. Share ownership, not content topic, is what makes this out-of-role.

**FLAG ANSWERED — Q13 (corrected):** `access_request_queue_20260526.csv` — opened from `\\Nh-fs-01\hr\2026-05\AccessRequests`, confirmed via `ShellLinkCreateFileEvent`.

**Key technique — `DeviceFileEvents` couldn't prove this on its own.** It showed the local `.lnk` and the local copy landing in `Documents\SupportReview`, but not the original network path. `DeviceEvents`' `ShellLinkCreateFileEvent` (with `AdditionalFields.ShellLinkWorkingDirectory`) was the only place that original path actually showed up — a good example of needing the fourth table (`DeviceEvents`) when the other three don't have the full picture.

**Retrospective — the full chain of why this took so many attempts:**
1. **Wrong device first.** Started on `nh-wks-it-01` looking for file events, but file telemetry logs on the device where the file *lives*, not the requesting device. Had to pivot to `nh-fs-01`.
2. **Wrong field once there.** `InitiatingProcessAccountName` is blank for pure SMB/network access (no local initiating process on the file server). Correct field, `RequestAccountName`, only surfaced by running `getschema` instead of guessing.
3. **Wrong time column.** `Timestamp` was unreliable on this table; `TimeGenerated` was consistently populated. Cost several empty-result queries before testing both.
4. **The structural mistake: `DeviceFileEvents` only logs create/modify/delete/rename — never a plain "open."** The actual moment he opened the HR file from the share could never show up there. Had to pivot to `DeviceEvents`' `ShellLinkCreateFileEvent` (Windows' "Recent files" shortcut creation), which happens to capture the original network path in `AdditionalFields.ShellLinkWorkingDirectory`.
5. **The real trap once the right data was in hand: judging by filename instead of by location.** `employee_record_EMP-87291...txt` *sounded* like the obvious HR file and got submitted first — wrong, because its origin path was never confirmed. `access_request_queue_20260526.csv` sounded IT-adjacent (matches his actual job duties — "handles account access requests") so it looked safe to overlook — but the role matrix defines in-role by which **share** a file sits on, not what the file's content is about. It lived under `\\Nh-fs-01\hr\...`, so touching it at all was out of role regardless of topic. Content can mislead; location is the actual yardstick.

### Step 8 — Q14: staging folder + a better-filtering lesson

**FLAG ANSWERED — Q14:** `C:\Users\m.reed\Documents\SupportReview` — the three files (`access_request_queue_20260526.csv`, `employee_record_EMP-87291_20260527.txt`, `access_review_notes_20260528.txt`) were staged here before compression. The resulting `support_review_202605.zip` itself landed one level up, in `C:\Users\m.reed\Documents\` directly, not inside `SupportReview`.

**Targeted replication query (staging folder + zip only, not the full noisy window):**
```kql
DeviceFileEvents
| where DeviceName startswith "nh-wks-it-01"
| where InitiatingProcessAccountName =~ "m.reed"
| where TimeGenerated between (datetime(2026-05-29 01:43:00) .. datetime(2026-05-29 01:57:00))
| where FolderPath has "SupportReview" or FileName endswith ".zip"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Lesson — should have filtered `ActionType == "PowerShellCommand"` directly instead of pulling an unfiltered `take 20` and scanning for the `Compress-Archive` line:**
```kql
DeviceEvents
| where DeviceName startswith "nh-wks-it-01"
| where InitiatingProcessAccountName =~ "m.reed"
| where TimeGenerated between (datetime(2026-05-29 01:43:00) .. datetime(2026-05-29 01:57:00))
| where ActionType == "PowerShellCommand"
| project TimeGenerated, ActionType, AdditionalFields
```
General takeaway: once `summarize count() by ActionType` reveals a promising ActionType (like `PowerShellCommand` or `ShellLinkCreateFileEvent`), filter straight to it — don't fall back to an unfiltered `take N` and eyeball-scan when a direct filter is one line away.

**Screenshot confirmation (`nh-wks-it-01-mreed-supportreview-staging.png`):** query returns the single `FileCreated` row for `support_review_202605.zip`, `FolderPath` starting `C:\Users\m.reed\Documents\su...` (truncated in UI, but consistent with the full path already captured — the zip in `Documents` directly, not inside `SupportReview`), `InitiatingProcessFileName: powershell.exe`, timestamp 1:55:27.907 AM.

### Step 9 — The exfil channel: RDP drive redirection, not upload

**Compression confirmed via `DeviceEvents`/`PowerShellCommand` (17 rows, all one `Compress-Archive` invocation, 1:55:21.351–1:55:27.909 AM):** exact command — `Compress-Archive -Path "C:\Users\m.reed\Documents\SupportReview\*" -DestinationPath "C:\Users\m.reed\Documents\support_review_202605.zip" -Force`. Ran as an in-process PowerShell cmdlet — never spawned a separate process, so it was invisible to `DeviceProcessEvents` (same for the later copy step — see below).

**Copy-out command also never appeared as a process** — checked `DeviceProcessEvents` out to 2:00 AM, nothing after `net view \\tsclient` (1:56:12.371) except unrelated Windows Mail sync noise (`HxTsr.exe`, 1:59:29). Concluded it ran via Explorer GUI copy/drag-and-drop into the redirected client drive — no command line generated at all. Pivoted to `DeviceFileEvents` directly for the destination `FileCreated` event instead:

```kql
DeviceFileEvents
| where DeviceName startswith "nh-wks-it-01"
| where InitiatingProcessAccountName =~ "m.reed"
| where TimeGenerated between (datetime(2026-05-29 01:55:00) .. datetime(2026-05-29 02:00:00))
| where FolderPath has "tsclient"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Result:** `FileCreated`, `support_review_202605.zip`, **`\\tsclient\G\Temp\NimbusSupport\support_review_202605.zip`**, initiated by `cmd.exe`, at **1:57:17.810 AM**.

**Why `\\tsclient` specifically:** `net view \\tsclient` had already appeared in the earlier enumeration burst (1:56:12 AM) — `tsclient` ("Terminal Services client") is the standard Windows naming convention for RDP drive redirection: when enabled, the *client's own local drives* become reachable from inside the remote session at `\\tsclient\<drive letter>\...`. That's the mechanism behind the brief's "walked out through the session they were already sitting in" — no upload, no cloud service, no outbound network connection to catch, because the channel was RDP's own built-in drive redirection, already open and already trusted.

**FLAG ANSWERED — destination path (no filename):** `\\tsclient\G\Temp\NimbusSupport`

**Compression timestamp:** 1:55:27.622 AM (start of `Compress-Archive` command) / 1:55:27.909 AM (completion).

**Lesson:** Two separate cases in this same session where an action left no process-level trace at all — `Compress-Archive` and the file copy — because they ran as in-session PowerShell cmdlets or GUI operations rather than spawning new processes. `DeviceProcessEvents` alone would have missed both. Always have a fallback table in mind (`DeviceEvents`/`PowerShellCommand` for cmdlets, `DeviceFileEvents` for the resulting file write) when a process-level search comes up empty on something that clearly happened.

### Step 10 — Q17: proving no persistence (the first "prove the negative")

**Checked two independent paths across the FULL 25–30 May window (not just the exfil session):**

1. **Binary-based persistence tools** (`DeviceProcessEvents`, `FileName in~ ("schtasks.exe","sc.exe","reg.exe","at.exe")`) → **empty**.
2. **Native PowerShell cmdlet equivalents** (`DeviceEvents`/`PowerShellCommand`, `AdditionalFields has_any ("ScheduledTask","New-Service","Set-Service","Run","RunOnce","Persistence")`) → **empty**.

Checking only the binary tools would have left a blind spot — this hunt already proved cmdlet-only actions (`Compress-Archive`, the file copy) don't show up as processes at all. Checking both closes that gap.

**Accounting for the entries that DID appear near the exfil window** — `taskhostw.exe -RegisterUserDevice -NewAccount` and `taskhostw.exe Install $(Arg0)` (1:55:59–1:56:00 AM): both launched by `svchost.exe -k netsvcs -p -s Schedule` — the Windows Task Scheduler *service* itself, running as SYSTEM, not tied to `m.reed`'s session or account. This is routine built-in Windows scheduled-task infrastructure firing coincidentally during the window, not something the operator created.

**FLAG ANSWERED — Q17:** No persistence was established. The entries found belong to Windows' own built-in Task Scheduler service (SYSTEM-run device registration/telemetry tasks), not the operator.

**Lesson:** Proving a negative means checking every mechanism that could produce the outcome, not just the first one — and every entry found still needs to be individually accounted for (who/what actually owns it), not dismissed by assumption either. Same rigor both directions.

### Step 11 — Second proven negative: "one machine, not two"

**Question:** HR data was read — did the account ever actually run anything ON the file server itself, or was the file reached some other way?

**Two checks, both scoped to `nh-fs-01` directly, full 25–30 May window:**

1. **Process execution:**
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-fs-01"
| where InitiatingProcessAccountName =~ "m.reed" or AccountName =~ "m.reed"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-31))
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```
Result: **empty.** No process ever ran under this account on the file server.

2. **Logon check:**
```kql
DeviceLogonEvents
| where DeviceName startswith "nh-fs-01"
| where AccountName =~ "m.reed"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-31))
| project Timestamp, ActionType, LogonType, RemoteIP
```
Result: **39 `LogonSuccess` events, but all `LogonType: Network`**, sourced from `10.1.0.233` (`nh-wks-it-01`'s own internal IP, per the role matrix) — spanning both his normal in-role IT-share work (5/28) and the HR access (5/29).

**Reasoning:** `Network`-type logon is the automatic SMB authentication handshake that fires the instant any network share is accessed (e.g. typing `\\NH-FS-01\HR` in Explorer) — it validates credentials so the share can open, but establishes no session, no desktop, nothing executable. It's fundamentally different from the `RemoteInteractive` logon type found earlier on the workstation, which did grant an actual interactive session. These `Network` logons are routine — the same kind fired for his legitimate IT-share browsing too. What made 5/29 notable was never the logon mechanism, it's which share it reached (proven separately via `ShellLinkCreateFileEvent`).

**FLAG ANSWERED:** No, never ran anything on the file server. Reached via SMB network file-share access (`Network`-type logon, automatic share authentication) from his own workstation.

**Lesson:** A `LogonSuccess` result isn't proof of "they got onto the machine" — the `LogonType` field is what tells you whether that's an actual session (`Interactive`/`RemoteInteractive`) or just protocol-level authentication (`Network`). Same lesson as `LogonAttempted` earlier in this hunt: don't read a logon-table row at face value, check what kind of logon it actually is before drawing a conclusion from it.

### Step 12 — Q19: The honest read (root cause synthesis)

**FLAG ANSWERED — Q19 ✅ correct:**

> "External account takeover via RDP from two outside IPs — no malware, no persistence, no insider signs."

**Unpacked:**
- **What this was / who drove it / from where:** External credential-reuse takeover — an outside attacker driving `m.reed`'s account remotely over RDP, from two external IPs (`116.45.242.115`, then `45.131.194.61` ~12.5 min later). Not Mason Reed himself, not a local insider.
- **What's absent that rules out the alternatives:** No malware (no malicious binary, no persistence — proven negative, two independent checks, no C2, no code injection — every tool used was legitimate native Windows/PowerShell/RDP functionality, pure living-off-the-land) and no insider signs (two unrelated external IPs, a brute-force-then-succeed pattern against his own account, credential traced to public breach data, and a sharp behavioral split between the light session-1 orientation burst and the deep, deliberate session-2 HR enumeration).

**Full chain, tying every piece together:**
1. Public LinkedIn profile (Artefact 01) identified Mason Reed as a brand-new IT hire with access-provisioning duties, and leaked a personal Hotmail address.
2. That email appeared in 3 breaches (Artefact 02); the MySpace one is too old/hashed to matter, but the Apr 2025 Synthient credential-stuffing set is recent and plaintext — the plausible source of a still-valid reused password.
3. A cached internal IT doc (Artefact 03), leaked into a public document cache, named `NH-WKS-IT-01` as a remote-support endpoint, gave its public IP, and stated plainly "use domain credentials when prompted."
4. `116.45.242.115` brute-forced `m.reed`'s account specifically (3 fails, low volume, patient) and succeeded, establishing a `RemoteInteractive` (RDP) session at 1:28:27 AM.
5. A light orientation burst followed (`whoami, hostname, ipconfig /all, whoami /groups`).
6. `45.131.194.61` logged in via its own `RemoteInteractive` session 12.5 minutes later, with zero failed attempts — already holding valid credentials.
7. That second session ran deep enumeration: file server discovery, domain user/group enumeration, specifically querying the `NH-HR-Users` group — well outside `m.reed`'s IT-only role per the matrix.
8. HR data (`access_request_queue_20260526.csv`) was opened via SMB from `\\Nh-fs-01\hr\2026-05\AccessRequests` — reached from his own workstation, never executing anything on the file server itself (proven negative).
9. Material staged locally in `Documents\SupportReview`, compressed via PowerShell's `Compress-Archive` into `support_review_202605.zip`, then copied out through the RDP session's own redirected client drive to `\\tsclient\G\Temp\NimbusSupport` — no upload, no cloud service, no outbound connection to flag, because the channel was the already-open, already-trusted RDP session itself.
10. No persistence established (proven negative, two independent checks — binary tools and native cmdlets).

**Root cause:** Valid account compromise via public credential exposure and OSINT reconnaissance, enabled by a leaked internal document that told the attacker exactly which host to target and confirmed domain credentials would work — not a malicious insider, not malware.

**Files staged in the same `SupportReview` folder, same window (collection/staging pattern, not just browsing):**
| Time | File | Read |
|---|---|---|
| 1:53:07.996 | `access_request_queue_20260526.csv` | Plausibly in-role — his job description includes handling account access requests |
| 1:54:15.506 | **`employee_record_EMP-87291_20260527.txt`** | **Out of role — HR data (Q13 answer)** |
| 1:54:38.631 | `access_review_notes_20260528.txt` | Plausibly in-role |
| **1:55:27.908** | **`support_review_202605.zip`**, created by **`powershell.exe`** | **Likely compresses the above — staging for exfil, flagged for Phase 05** |

Note: `.lnk` shortcut artifacts (`SupportTickets.lnk`, `WorkstationBuilds.lnk`, `AccessRequests.lnk`, etc.) also appear in `AppData\Roaming\Microsoft\Windows\Recent\` around the same time, initiated by `explorer.exe` — these are normal Windows "recent files" jump-list entries auto-created whenever a file is opened via Explorer, not independently suspicious, but they do corroborate that these specific files were actively opened/navigated to (not just sitting there).

**Lesson:** When a folder-path filter (`has "NH-FS-01"`) returns nothing, the assumption baked into the filter (UNC-path access) may itself be wrong — e.g. a file could be reached via a mapped drive letter or already be local. Dropping the filter entirely and reviewing everything the account touched in the proven time window found the answer directly, and also surfaced the compression step (the zip) as a bonus — a good example of not over-filtering too early.

**Lesson:** A chain of empty results usually means a wrong assumption somewhere upstream (wrong device, wrong field, wrong time column) — not "no data." Troubleshoot systematically (check schema, drop filters one at a time, anchor time windows on already-proven events) rather than re-running the same shape of query with small tweaks. Also: useful evidence can surface as a side effect of troubleshooting a different question — capture it when it appears instead of only looking for what you set out to find.

### Step 13 — Q20: The guessing pattern (credential reuse vs. brute force)

**Question:** Prove the successful logon is credential reuse from the breach, not brute force — what separates the two.

**Evidence, already captured in Step 4's table:**
- 3 `LogonFailed` events, then `LogonSuccess`, all from **`116.45.242.115`**, all inside **~2 minutes** (1:26:21 AM → 1:28:22 AM).
- A real brute-force/spray tries dozens-to-thousands of guesses over a sustained window from many sources (that's the noise floor documented separately on this box). 3 attempts in 2 minutes from one address is the opposite shape — a short list of near-certain candidates, not blind guessing.
- That shape matches an attacker who already holds a specific password (or a couple of close variants of it) sourced from the Synthient breach data (Artefact 02) — trying a handful of known-plausible values and landing on the right one fast, rather than exhausting a wordlist.

**FLAG ANSWERED — Q20 ✅ correct:** "3 failed logons, then success, from `116.45.242.115` in ~2 minutes — matches the Synthient-breach password, not a spray."

**Lesson:** Failure *count* and *time span* are the actual discriminators between brute force and credential reuse — not just "were there failures before the success." Few attempts + tight window + single source = reuse; many attempts + long window + many sources = spray/brute force.

### Step 14 — Q21: The session switch (the 10-minute gap)

**Question:** What happened at the start of the second session that explains the ~10-min gap between the first and second command bursts.

**Answer, from Step 4's logon table:** the gap is explained by a source-IP change — a brand-new `RemoteInteractive` logon from **`45.131.194.61`** at **1:40:59.113 AM**, with its own `Network`-type successes preceding it (starting 1:28:43 AM, just 16 seconds after the first session's interactive logon) and zero failed attempts of its own.

**FLAG ANSWERED — Q21 ✅ correct:** New `RemoteInteractive` logon from `45.131.194.61` at 1:40:59.113 AM — a different source IP opened a fresh session, explaining the gap between the two command bursts.

**Lesson:** The "gap" wasn't idle time — it was session-teardown/re-establishment from a second address. A quiet stretch in process telemetry doesn't mean nothing happened; check the logon table for a new session starting in that window before assuming inactivity.

### Step 15 — Q22: The channel check (proving premeditation)

**Question:** the one command, before the archive left, that proves the operator checked what the RDP channel offered first — separating premeditated exfil from an opportunistic copy.

**Answer, from Step 5's Burst 2 table:** `net  view \\tsclient`, run at **1:56:12.371 AM** — roughly a minute before the zip was created (1:57:17.810 AM). This enumerates what's shared/reachable through the Terminal Services client redirection before actually using it as a destination — proof the operator deliberately checked the channel existed and was usable, rather than stumbling onto it while copying.

**FLAG ANSWERED — Q22 ✅ correct:** `net  view \\tsclient` (raw log double-space preserved, as with other `net`/`ipconfig` commands in this hunt).

**Lesson:** A discovery command run immediately before the action it enables (here, `net view` on the exact UNC root used seconds later for the exfil write) is the evidence line between "happened to notice" and "planned it" — sequence and proximity matter as much as the command itself.

### Step 16 — IR1: First containment (reasoning, not telemetry)

**Question:** Clinic wants to call this a curious new starter and just reset the password. First containment action, and why a reset alone isn't enough.

**FLAG ANSWERED — IR1 ✅ correct:** Disable the `m.reed` account and isolate `nh-wks-it-01` from the network, immediately — not just a password reset. A reset doesn't terminate an already-established session (the attacker could still be active in an RDP session right now) and doesn't undo the fact that the credential is already compromised and data already left — containment has to cut access at the account/host level while the incident is investigated, not just rotate a secret going forward.

**Lesson:** First move on a confirmed account compromise: kill live access (disable account + isolate host), not just prevent future access (password reset). The two are different problems — one stops what's happening now, the other only stops what happens next.

### Step 17 — IR2: The disclosure question

**Question:** One staged/exfiltrated file contains personal data. What kind, and what obligation does that create?

**FLAG ANSWERED — IR2 ✅ correct:** `employee_record_EMP-87291_20260527.txt` is employee personal data (PII), not just internal business records — its exfiltration triggers a data breach notification obligation (notifying the affected individual, and potentially regulators), converting this from an internal IT cleanup into a legal/compliance disclosure matter.

**Lesson:** Content classification changes the response track. Once one of the exfiltrated files is confirmed to be personal data rather than operational data, the incident isn't just a technical containment problem anymore — it has a legal notification clock attached, and that has to be flagged early, not discovered later while writing the report.
