# Maintainer review — 2026-09-15

## Decision

**Do not merge any of the four PRs as submitted.** They address real maintenance
problems, but the proposed global replacements are not compatible with the
verified add-on schemas. Preserve the contribution and supersede them with the
reviewed compatibility work in this branch after runtime testing.

**Review complete; consolidated draft PR candidate prepared; release BLOCKED pending Splunk
runtime and release evidence.** This is an A2 maintenance candidate,
`2.1.0-dev.1`, not a production or Cloud approval. The maintainer authorized
publishing the branch as one draft PR. Its closing references cover the four
superseded PRs and issues #10, #12, and #13 when the replacement merges. Cloud
vetting (#4) and the maintenance/fork discussion (#14) remain separate follow-ups.
No merge or release is part of this consolidation.

Scope: all four open PRs, all five open issues, all 12 XML views/navigation, all
77 saved searches (25 scheduled), app configuration, permissions, and setup docs.
The [complete saved-search inventory](search-inventory.md) records the baseline
classification of every search.
The baseline was `5c6e54e869f2b536c482c3534a16835725b44386`, matching `origin/master`
and the remote master at review start. Independent agents reviewed field
semantics, onboarding/issues, dashboards, and the entire saved-search inventory.
A separate Sol review inspected the implementation.

## Pull request decisions

| PR / captured head | Finding | Maintainer action |
| --- | --- | --- |
| [#15 — ComputerName](https://github.com/MHaggis/sysmon-splunk-app/pull/15), `422471e406c91ccfc23de44349a26154163f6a75` | `ComputerName` is a real reported pipeline variant, but official XML extraction produces `Computer`. The patch also introduces `ComputerNameName`. | Request changes / supersede. Normalize both event-computer names into an app field. |
| [#16 — sourcetype](https://github.com/MHaggis/sysmon-splunk-app/pull/16), `b895dab94df4cdb2d16c7d24ff18d8ef9b74776b` | `WinEventLog:Sysmon` is not a universal Sysmon sourcetype; the change can hide all current-TA data. | Supersede with a source/channel selector plus exact Sysmon-only legacy fallbacks, and require an index override. |
| [#17 — process to Image](https://github.com/MHaggis/sysmon-splunk-app/pull/17), `efe7b72f4f0c92c1838e3811bf320d9fcd47ba58` | `Image=powershell.exe` does not match a full Windows image path. CIM `process` can mean command line; legacy `process` meant basename. Inherits #15 and the sourcetype change. | Supersede with distinct app process-name/path fields and consistent filters/drilldowns. |
| [#18 — network field casing](https://github.com/MHaggis/sysmon-splunk-app/pull/18), `8c05b20afde82d2b9fef7a8358b14197b413a235` | Native field is `DestinationIp`, not `DestinationIP`; hostname-only panels omit unnamed peers. Inherits #15 and the sourcetype change. | Supersede with normalization and hostname-to-IP fallback. |

PRs #17/#18 are cumulative branches, not four independent changes to stack.
The captured PRs have no status-check results. “Mergeable” only describes Git
conflicts; it is not evidence that searches work.

## Why these conclusions are supported

- Microsoft's [Sysmon schema](https://github.com/microsoft/MSTIC-Sysmon/blob/main/windows/schemas/sysmonv13.30_4.81.xml)
  uses `Image`, `SourceIp`, `DestinationIp`, `DestinationHostname`, and
  `DestinationPort`. Splunk field names are case-sensitive.
- Historical TA 8.0 [immutable source](https://github.com/dimarra/TA-Microsoft-Sysmon/tree/fef9799ab6668028820b8f9b2b8fbb3ad6b4a42b)
  extracts `Computer` and derives a basename `process` from `Image`.
- The current [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
  is 5.0.1. Its inspected package uses the Sysmon-specific `source`, normalizes
  legacy sourcetypes to generic `XmlWinEventLog`, extracts `Computer`, and maps
  Event 1 `process` from `CommandLine`. Version 5.0.0 used lowercase
  `xmlwineventlog`, reinforcing source-based selection.
- [Splunk CIM Endpoint](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/6.0/data-models/endpoint)
  distinguishes command string, executable name, and executable path. The app
  must preserve that distinction instead of choosing a spelling globally.

Inspected official TA package provenance:

| Package | SHA-256 |
| --- | --- |
| [5.0.0](https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/splunk-add-on-for-sysmon_500.tgz), linked by [Splunk security_content](https://github.com/splunk/security_content/blob/4cd62e811c5eddf1245c780d48823d7b38998566/contentctl.yml) | `3b42abf255fbd794cdfa588c3ad152e63f4b62e5665aad0b2c8dd7a23a3b5818` |
| [5.0.1](https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/splunk-add-on-for-sysmon_501.tgz), inspected from the same Splunk Attack Range bucket | `e02c0a5801b714f5be4f570348727c3ba60d2b332d6e810d3ea8f5e568c7fe38` |

Package inspection proves configuration contents, not successful extraction in a
particular deployment. That final check requires the real TA and event samples.

## Issue dispositions and proposed replies

These replies are drafts; none has been posted. Close bug reports only after the
corresponding release and reporter/runtime confirmation.

### [#10 — Computer or ComputerName](https://github.com/MHaggis/sysmon-splunk-app/issues/10)

**Keep open until compatibility fix is released.**

Draft: “Thanks for identifying this. The field depends on the collection/add-on
pipeline, and the supported XML add-on still extracts `Computer`. The maintenance
candidate accepts both `Computer` and `ComputerName` without substituting the
collector host. This should address your case while preserving other
installations. It is awaiting runtime validation before release.”

### [#13 — app sees no data](https://github.com/MHaggis/sysmon-splunk-app/issues/13)

**Keep open for verification; link it to the selector/setup correction.**

Draft: “The old macro can miss newer Sysmon inputs. The candidate selects the
Sysmon source/channel with legacy fallbacks. Please compare `index`, `source`, and
`sourcetype` from a working search with the app's `sysmon` macro, set the intended
index explicitly, and check extraction in this app's search context. A universal
switch to `WinEventLog:Sysmon` would break other supported configurations.”

### [#12 — threathunting index / permissions](https://github.com/MHaggis/sysmon-splunk-app/issues/12)

**Documentation/support issue; answer, then close when resolved.**

Draft: “This app does not require an index named `threathunting`. Your role must
have access to the index holding Sysmon events, and the macro should explicitly
select it. Without `index=`, Splunk searches the role's default indexes, which can
be a smaller set than its allowed indexes. The updated README separates those
steps.”

The quoted `threathunting` instruction is absent from the reviewed repository;
its external origin is unconfirmed. See [Splunk authorize.conf](https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.2/configuration-file-reference/10.2.2-configuration-file-reference/authorize.conf)
for the distinction between allowed and default indexes.

### [#4 — Cloud vetting](https://github.com/MHaggis/sysmon-splunk-app/issues/4)

**Keep open as the Cloud release tracker.**

Draft: “The earlier Cloud-vetting promise did not result in a verified current
release. The candidate fixes package metadata and Simple XML 1.1 declarations,
and makes dashboard input behavior explicit. Cloud validation, authenticated
runtime testing, and publication are still required. This issue will stay open
until those results are available.”

The [public app](https://splunkbase.splunk.com/app/3544) is archived at 2.0.0, with
an Enterprise listing. A local AppInspect pass does not grant Cloud approval.
[Classic Simple XML is still documented](https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/simple-xml-dashboards/10.2/manage-and-share-dashboards/manage-dashboards-that-need-jquery-updates);
a Dashboard Studio rewrite is not required just to address the identified
version declaration defect.

### [#14 — still maintained / permission to fork](https://github.com/MHaggis/sysmon-splunk-app/issues/14)

**Maintainer response needed; avoid promising a release date.**

Draft: “Your concern was fair: the last public version dates to 2018. Maintenance
work is now being reviewed, with no release date promised yet. The source is
MIT-licensed, including permission to modify and distribute it while retaining
the copyright/license notice. Thanks for offering to contribute improvements.”

## Local changes

- Added app-owned compatibility fields and a Sysmon-specific selector. Preserved
  raw/CIM fields, the input data, existing saved-search names, and author credits.
- Migrated dashboard/report host, user, process and network references to the
  defined field contract. Separated executable basename and full-path searches.
- Updated all 12 roots to Simple XML 1.1; initialized defaults and enabled time
  changes; corrected finder statistics and investigation/timeline filters.
- Fixed the missing `>5` aggregation threshold and the apparently inverted second
  Visual Studio parent exclusion. The latter is an inference from the alert's
  stated intent and must be checked against deployment-specific tuning.
- Corrected “Suspicious Exe Path” to match full paths with explicit directory
  prefixes/wildcards, including the Recycle Bin.
- Fixed the unterminated rundll parent-command string and bitsadmin's whole-field
  `/transfer` equality. Corrected bare `Image`/`ParentImage` executable comparisons.
- Added explicit time bounds to all searches (previously unbounded reports now
  default to 24 hours), removed author-specific optional visualization/action
  references, and deduplicated display field lists.
- Added candidate SemVer/identity metadata, Cloud admin ACL compatibility,
  installation/troubleshooting docs, deterministic packaging, static regression
  guards, and generated read-only SPL fixture checks.

## Deliberately unresolved legacy content

These are **known limitations**, not approved detections. Fixing their intent
requires representative positive/negative events and a separate content pass:

- Eventviewer/sdclt registry rules use `HKEY_USERS` rather than Sysmon's `HKU` and
  omit the variable user SID/path structure. A root-only replacement is inadequate.
- “Shellcode Injected from Office” uses an exact bare `TargetImage` and incomplete
  Office source path. Its technique label also needs validation.
- “Suspicious binary launch location” contains `debut`, an apparent typo whose
  intended path needs confirmation.
- Two `net` reports contain double-space command patterns. WCE contains a likely
  `[az0-9]` regex typo. Several command-line rules are too exact or incomplete.
- “Runs from SYSVOL” actually searches System Volume Information. Saved-search
  identity was preserved; renaming or changing detection intent needs review.
- Twenty-one schedules share `*/20` boundaries. Keep scheduling/tuning explicit;
  measure load and choose staggering with coverage checks in the target system.
- Reports that display `EventDescription` and MD5 still depend on extraction and
  the selected Sysmon configuration. This is not coverage for every modern
  Sysmon event or ATT&CK technique.

No external notification action was enabled; the 25 scheduled alerts retain
Triggered Alerts tracking. Do not enable or advertise the whole library as
validated detection content on the strength of this maintenance patch.

## Evidence and next action

The reproducible test commands and runtime matrix are in [validation.md](validation.md).
AppInspect baseline: **95 passed checks, 2 failed checks, 4 warnings, 0 errors**.
The failures were semantic versioning/identity and the 12 missing Simple XML 1.1
attributes. The warnings included 25 missing scheduled upper time bounds.
Candidate local results: **15 regression tests passed; static checks passed for
12 views, 77 saved searches and 120 queries; AppInspect 4.3.1 reported 102 passed
checks, 0 failures/errors, 2 warnings and 1 skipped check**. The remaining warnings
are the private-app update-check heuristic (`check_for_updates=true` is intentional
for this existing public app) and slash characters in the exact legacy Sysmon
sourcetype names (retained for compatibility). The skipped check requires an
optional `app.manifest`, which is not supplied. These items need review in the
final publication workflow; do not rename existing input sourcetypes merely to
suppress a warning. Exact package hash and full machine-readable reports are
recorded under `.context/review/`.

**Passed:** repository/PR/issue inventory, primary-source/add-on inspection,
independent static reviews, local regression checks, XML parsing, diff checks,
and AppInspect with the noted warnings.

**Failed / unresolved:** release gate; documented legacy detection defects and
unverified operational behavior prevent a production-ready claim.

**Skipped:** real Splunk SPL execution, add-on ingestion/extraction and base-search
filtering, authenticated browser/console/network checks, Cloud AppInspect API
vetting, and a published release. No Splunk test runtime or target deployment was
available in this workspace. Read-only SPL fixtures and an explicit acceptance
matrix are prepared for the next gate.

Next: install the candidate with the intended TA in a test Splunk environment,
run the positive/negative searches and authenticated dashboard checks, resolve
any resulting defects, and complete the Cloud/Splunkbase release workflow if
Cloud publication is intended. The draft PR and its cross-references are
authorized; the individual issue replies remain drafts. Merge and publication
remain separate decisions after validation.
