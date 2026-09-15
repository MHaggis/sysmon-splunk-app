# Saved-search inventory at the review baseline

This classification covers committed baseline `5c6e54e` before the maintenance
patch. “Accept” means structurally plausible on static review, not a runtime
or detection-efficacy pass. See [maintenance-review.md](maintenance-review.md)
for the corrected subset and unresolved items; line ranges below refer to the
baseline, not the candidate.

## Complete inventory and static classification

Legend: **Accept** = no specific static logic defect found beyond the global schema/runtime dependencies; **Fix** = high-confidence defect; **Validate** = plausible coverage/compatibility issue requiring representative events; **Duplicate** = redundant saved search.

| # | Stanza (lines) | Mode | Classification | Audit note |
|---:|---|---|---|---|
| 1 | `Powershell - EventDescription` (2-16) | Report | Accept | Basic aggregation; validate legacy `process`. |
| 2 | `Sysmon - Top EventDescription` (17-31) | Report | Accept | Broad 24h report by design. |
| 3 | `Sysmon - Parent to Child` (32-47) | Report | Accept | Raw `NOT splunk` is coarse but intentional-looking. |
| 4 | `EventDescription - by process, Commandline` (48-60) | Report | Accept | Uses caller/UI time range because no dispatch range is stored. |
| 5 | `Powershell - All PoSh by Computer` (61-74) | Report | Validate | Depends on `Computer` and `process` TA fields. |
| 6 | `net - All net usage` (75-90) | Report | Validate | Depends on `Computer` and `process`; otherwise coherent. |
| 7 | `wmic.exe - all wmic execution` (91-106) | Report | Validate | Same schema dependency. |
| 8 | `CommandLine - By computer, process` (107-120) | Report | Validate | Same schema dependency. |
| 9 | `Net - Group, localgroup` (121-134) | Report | **Fix** | Literal double spaces in both command patterns (line 133). |
| 10 | `Users by Computer` (135-148) | Report | Validate | `Computer` / lowercase `user` compatibility. |
| 11 | `Commandline by user` (149-162) | Report | Validate | Lowercase `user` compatibility. |
| 12 | `Net - net view` (163-176) | Report | **Fix** | Literal double space and exact command value (line 175). |
| 13 | `Windows Credential Editor` (177-190) | Report | **Fix** | Bare `ParentImage`; probable `[az0-9]` UUID regex typo (line 189). |
| 14 | `mimikatz` (191-204) | Report | Accept | SPL precedence correctly scopes macro over all OR terms. |
| 15 | `gsecdump` (205-218) | Report | Validate | Regex expects a backslash in `process`; behavior depends on TA field semantics. |
| 16 | `wmic - process call create` (219-232) | Report | Validate | Legacy `process` dependency; command pattern coherent. |
| 17 | `wmiprvse - parent execution` (233-248) | Report | **Fix** | Bare filename against `ParentImage` (line 247). |
| 18 | `wmic - /node` (249-262) | Report | Validate | Legacy `process` dependency; command pattern coherent. |
| 19 | `vssadmin - delete` (263-274) | Report | Accept | Event 1 and three command-line conditions are explicit. |
| 20 | `taskeng - parentproc all` (275-290) | Report | **Fix** | Bare filename against `ParentImage` (line 289). |
| 21 | `schtasks - run` (291-304) | Report | Accept | Intentionally selects remote `/Run` with `/s`. |
| 22 | `schtasks - delete` (305-318) | Report | Accept | Intentionally selects remote `/Delete` with `/s`. |
| 23 | `schtasks - create` (319-332) | Report | Accept | Intentionally selects remote `/Create` with `/s`. |
| 24 | `schtasks - change` (333-346) | Report | Accept | Intentionally selects remote `/Change` with `/s`. |
| 25 | `schtasks - all` (347-362) | Report | Validate | Basic aggregation; legacy field dependency. |
| 26 | `rundll32 - suspicious execution` (363-379) | Report | **Fix** | Exact bare `Image` and bare parent paths make branches ineffective. |
| 27 | `psexecsvc - all` (380-393) | Report | **Fix** | Bare filename against `ParentImage` (line 392). |
| 28 | `psexec - IMPHASH not psexec.exe` (394-407) | Report | Accept | Explicit wildcard on exclusion; hash criterion is clear. |
| 29 | `psexec - IMPHASH` (408-421) | Report | Accept | Hash criterion is clear; hash age/coverage is a content decision. |
| 30 | `powershell - invoke-command` (422-435) | Report | Accept | Uses suffix wildcard for path-tolerant legacy process match. |
| 31 | `at execution` (436-451) | Report | **Fix** | Bare filename against `ParentImage` (line 450). |
| 32 | `wsmprovhost - powershell` (452-467) | Report | Accept | `ParentImage` has a leading wildcard; title is somewhat broader than search. |
| 33 | `msbuild - all` (468-483) | Report | Validate | Legacy field dependency. |
| 34 | `rundll32.exe - all` (484-499) | Report | Validate | Legacy field dependency. |
| 35 | `rundll32.exe - Control_RunDLL` (500-515) | Report | Accept | Command containment pattern is plausible. |
| 36 | `rundll32.exe - DllRegisterServer` (516-531) | Report | Accept | Raw keyword plus process constraint is plausible. |
| 37 | `rundll32.exe - \\roaming\\ execution` (532-547) | Report | Accept | Raw path keyword is coarse but scoped. |
| 38 | `cscript - http` (548-563) | Report | Accept | Raw `http` term is coarse but scoped. |
| 39 | `wscript - js execution` (564-579) | Report | Accept | Raw `.js` term is coarse but scoped. |
| 40 | `wscript - vbs or vbe execution` (580-595) | Report | Accept | OR is correctly scoped under SPL search precedence. |
| 41 | `wscript - Suspicious rar/zip userprofile execution` (596-611) | Report | Validate | Precedence scopes it, but raw punctuation terms need runtime fixtures. |
| 42 | `netsh - all` (612-627) | Report | Validate | Legacy field dependency. |
| 43 | `bitsadmin - all` (628-643) | Report | Validate | Legacy field dependency. |
| 44 | `Net - IPC$ access` (644-658) | Report | Accept | Raw `ipc$` term is scoped to `net.exe`. |
| 45 | `installutil - all` (659-673) | Report | Validate | Legacy field dependency. |
| 46 | `Powershell - EncodedCommand` (674-687) | Report | Accept | Broad abbreviation list is intentional; runtime tune false positives. |
| 47 | `Critical Process` (688-705) | Report | Validate | No EventCode constraint; validate meaning of `process` across TA events. |
| 48 | `IOC - svchost.exe not run by services.exe` (706-723) | Alert | **Fix** | Raw path/bare filename comparisons (lines 721-722). |
| 49 | `IOC - >5 Critical Process in 10m` (724-742) | Alert | **Fix** | No `count > 5`; likely wrong positive ParentImage constraint (line 741). |
| 50 | `IOC - Suspicious Driver Loaded from Temp` (743-759) | Alert | Accept | Event 6 / `ImageLoaded` and temp pattern align with intent. |
| 51 | `IOC - Suspicious Exe Path` (760-775) | Alert | **Fix** | Path/name fields are mixed and patterns omit necessary prefixes (line 774). |
| 52 | `IOC - Eventviewer UAC Bypass` (776-792) | Alert | **Fix** | Wrong Sysmon registry root and missing variable user path (line 791). |
| 53 | `IOC - UAC Bypass sdclt` (793-809) | Alert | **Fix** | Wrong Sysmon registry root and missing variable user path (line 808). |
| 54 | `IOC - Powershell Suspicious Strings` (810-829) | Alert | Accept | SPL precedence correctly scopes `(Invoke* OR IEX OR Download*)`. |
| 55 | `IOC - Abnormally long Powershell Command` (830-846) | Alert | Accept | Explicit Event 1, process, length threshold. |
| 56 | `IOC - Commands run from Office Doc/Browser` (847-865) | Alert | Validate | Precedence is correct; browser/Office path list is obsolete/narrow and needs coverage fixtures. |
| 57 | `IOC - Suspicious binary launch location` (866-882) | Alert | **Fix** | Likely typo `windows\\debut` at line 881; other path branches are coherent. |
| 58 | `IOC - Suspicious execution of rundll - User Profile/Browser` (883-899) | Alert | **Fix** | Unterminated escaped quote at line 898; brittle exact parent command line. |
| 59 | `IOC - Certutil Decode in Appdata` (900-916) | Alert | Validate | Pattern likely misses absolute AppData paths (line 915). |
| 60 | `IOC - Download from bitsadmin` (917-933) | Alert | **Fix** | `CommandLine="/transfer"` is too exact for a process command line (line 932). |
| 61 | `IOC - MSHTA Spawning Windows Shell` (934-950) | Alert | Accept | Parent path wildcard plus child-name group is coherent. |
| 62 | `IOC - Process Created by MMC` (951-967) | Alert | Validate | Main logic is coherent; exact negative command-line value may not exclude intended variants. |
| 63 | `IOC - Shellcode Injected from Office` (968-983) | Alert | **Fix** | Bare `TargetImage` and incomplete `SourceImage` path pattern (line 982). |
| 64 | `IOC - Suspicious Powershell Exe from Scripting` (984-999) | Alert | **Fix** | Bare filenames against `ParentImage` (line 998). |
| 65 | `IOC - Suspicious Script Execution` (1000-1016) | Alert | Accept | Process and extension groups are explicit; duplicate `.vbe` is harmless cleanup. |
| 66 | `IOC - Vssadmin Activity` (1017-1033) | Alert | Validate | Exact full-command phrases are likely too narrow; requires fixtures. |
| 67 | `IOC - MSHTA JavaScript Invoke` (1034-1051) | Alert | Accept | Explicit process and command containment. |
| 68 | `IOC - Powershell Suspicious Strings 01` (1052-1072) | Alert | Accept | Coherent scheduled version; tune CCM exclusion with data. |
| 69 | `T1086 - Powershell Suspicious Strings` (1073-1092) | Report | **Duplicate** | Same SPL as #68, unscheduled; ATT&CK ID is stale. Consolidate after usage check. |
| 70 | `T1015_Accessibility_Backdoor` (1093-1114) | Report | Accept | Multiline grouping and path wildcards are coherent; ATT&CK label is stale. |
| 71 | `IOC - Disable Startup Repair` (1115-1132) | Alert | Accept | Command patterns match stated behavior. |
| 72 | `Runs From RECYCLEBIN` (1133-1149) | Report | Accept | SPL precedence correctly scopes the two raw path terms. |
| 73 | `Runs from SYSVOL` (1150-1165) | Report | **Fix** | Search targets System Volume Information, not SYSVOL (line 1164). |
| 74 | `T1117 - REGSVR Proxy Execution` (1166-1186) | Alert | Accept | Process plus URL-bearing `/i:` pattern is coherent; ATT&CK label is stale. |
| 75 | `rundll32.exe - All Executions` (1187-1203) | Report | Validate | Near-duplicate of #34 with a different aggregation; check dashboard/user references before consolidation. |
| 76 | `T1085 - rundll32 with javascript arg` (1204-1223) | Alert | Accept | Explicit process and command containment; ATT&CK label is stale. |
| 77 | `IOC - Suspicious msiexec execution` (1224-1241) | Alert | Accept | Process plus `/i` and HTTP containment is coherent; add EventCode 1 only if runtime data shows ambiguity. |
