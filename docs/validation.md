# Validation and release gates

The [CI workflow](ci.md) automates the static/package checks and preserves the
tested candidate and reports. It also rejects unreviewed changes to AppInspect's
known warnings/skips. A green CI run is not Splunk runtime or Cloud approval.

## What local checks establish

`python3 -m unittest discover -s tests -v` and `python3 scripts/validate_app.py`
check package structure, selector coverage/exclusion fixtures, field-name
contracts, a basename regex fixture, known query regressions, XML declarations,
and time bounds. They **do not run SPL**, execute the add-on, or render dashboards.

`python3 scripts/package_app.py` writes a repeatable allowlisted package under
`.context/dist/`. It excludes local overrides, credentials, Git, tests, scripts,
and Conductor evidence. Inspect that exact package with AppInspect; record its
SHA-256 with the result. Local CLI results do not grant Cloud approval.

## Field contract (SM-01 / SM-02)

The app adds independent calculated fields scoped to its app through
`metadata/default.meta`. Source stanzas handle the supported add-on's canonical
Sysmon source; explicit Sysmon-only sourcetype stanzas cover compatibility inputs.
No generic Windows sourcetype stanza is added.

| App field | Meaning / source |
| --- | --- |
| `sysmon_computer` | First available `Computer`, `ComputerName`. Missing identity remains missing; collector `host` is not a fallback. |
| `sysmon_process_path` | Native `Image` without modification. |
| `sysmon_process_name` | Basename from `Image`; never parsed from CIM `process`/command line. |
| `sysmon_parent_process_name` | Basename from `ParentImage`. |
| `sysmon_user` | `User`, then existing `user`. |
| `sysmon_src_host` | Native nonempty/non-`-` source hostname, native source IP, then legacy source host/IP. |
| `sysmon_dest_host` | Native nonempty/non-`-` destination hostname, native destination IP, then legacy destination host/IP. |
| `sysmon_dest_ip` | `DestinationIp`, legacy `DestinationIP`, then `dest_ip`. |
| `sysmon_dest_port` | `DestinationPort`, then `dest_port`. |
| `sysmon_protocol` | `Protocol`, then `protocol`. |

Raw fields and add-on/CIM names are preserved. Calculated fields run in parallel,
so no app expression references another `sysmon_*` calculated field. Legacy
fallback names that are themselves calculated by a TA cannot be assumed to exist
at this stage; supported TA extraction uses the native fields listed first.
Custom pipelines must validate their actual field timing.

### Read-only synthetic SPL cases

```sh
python3 scripts/generate_splunk_checks.py
```

Paste each `search` from `.context/review/splunk-normalization-checks.json` into
Splunk Search. Each successful fixture returns **zero failure rows**, without a
job warning/error. Cases cover current and older field forms, Windows paths,
UNC paths, command-line versus image semantics, absent/placeholder hostnames,
IPv6, and absent endpoint identity. This evaluates the shipped expressions using
`makeresults`; it does not prove `props.conf` scoping or real XML extraction.

### Real input/extraction matrix (required before release)

Test the candidate against the exact installed version of each supported TA.
At minimum test current Splunk Add-on for Sysmon 5.0.1 and one explicitly chosen
legacy profile before advertising legacy support. Record Splunk, TA, and Sysmon
versions, collection method, source/sourcetype, and app package hash.

Use an isolated test index containing representative Sysmon events 1, 3, 5, 6,
7, 8, 10, 11, 12, 13, 14, 15, and 16 as available to the dashboard under test.
Include a non-Sysmon Windows event as a selector negative case. Test both direct
collection and WEC when WEC support is claimed. Use approved, non-sensitive test
events and record fixture provenance.

In this app's Search context:

```spl
`sysmon` earliest=-24h latest=now
| stats count by index source sourcetype EventCode
```

```spl
`sysmon` EventCode=1 earliest=-24h latest=now
| table Computer ComputerName host Image ParentImage CommandLine process
    sysmon_computer sysmon_process_name sysmon_process_path sysmon_parent_process_name
```

```spl
`sysmon` EventCode=3 earliest=-24h latest=now
| table DestinationHostname DestinationIp DestinationPort Protocol
    sysmon_dest_host sysmon_dest_ip sysmon_dest_port sysmon_protocol
```

Compare base-event counts with the intended index/channel population. Verify the
computed fields are available when used as **base-search filters**, not just in a
`table`. Confirm the app's additions do not override native/CIM fields or leak
into unrelated app contexts. Check effective configuration with `btool` on an
Enterprise test installation where available.

## Dashboard acceptance (SM-03)

Open all 11 navigable views and the legacy overview under an authenticated user
with intended index permissions. Record screenshots, console errors, network or
search-job messages, and displayed counts; redact credentials and personal data.

- Defaults run on first load; time-picker changes update results. Submit applies
  edited text filters.
- Investigator respects endpoint and user filters, including spaces, quotes and
  backslashes. Quotes must remain values rather than additional SPL.
- Network Connections filters destination host/IP, port, protocol and image.
  Missing DNS names still appear by IP. Geolocation uses IP, not hostname.
- Process Finder uses process-creation events with an available MD5. Two images
  sharing one MD5 on one host must both survive. For a filtered population of
  four hosts and a particular hash/path seen on one, prevalence is 25%. Duplicate
  events do not inflate host prevalence; earliest timestamp is chronological.
  Missing hashes are excluded deliberately. Validate numeric input and zero-data
  behavior.
- Timeline user input selects that field; clicking LogonGuid updates the chart.
  Clicking a process series filters detail to that same field/value. Changing
  logon selection clears stale detail. Test paths with spaces and backslashes.
- Confirm event-code labels against actual Sysmon events; do not infer an
  ingestion failure from an event type disabled in the Sysmon configuration.

## Saved-search acceptance (SM-04)

Parse and execute all 77 searches in the candidate app context. For each changed
predicate, run a positive and negative example. Record the exact result set and
search-job errors/warnings, not just whether the job completed.

Priorities:

1. Full-path PowerShell/WMIC/etc. must match basename predicates, while another
   executable merely mentioning that name in its command line must not.
2. For “>5 Critical Process in 10m”, five events on one endpoint in one bin must
   not match; six must match. Six events split over endpoints/bins must not
   combine. Confirm both Visual Studio parent-path exclusions. The second
   exclusion corrects an apparent inverted allowlist; confirm it matches your
   intended operational tuning before enabling the candidate schedule.
3. The rundll browser query must parse and match a representative full command
   line. A browser parent outside the intended pattern must not match.
4. Test bitsadmin `/transfer` with actual command lines and argument boundaries.
5. Verify parent-basename exclusions against native `ParentImage` full paths.
6. Verify all 25 schedules, time bounds, Triggered Alerts behavior, and scheduler
   load. No notification action was enabled by this maintenance patch.

The maintenance report lists older detection defects that remain open. Treat
those searches as unvalidated investigation content until independently tested.
Do not claim the entire legacy detection library is production-ready.

## Upgrade and release (SM-05 / SM-06)

- Compare existing `local/` macros, dashboards, saved searches and knowledge
  object permissions; local customizations may override all shipped fixes.
- Review the normalization schema and operational query changes independently.
- Run the current Splunk AppInspect checks on the exact final package. For Cloud,
  follow the AppInspect API/vetting and target deployment's installation process.
- Reconcile version and package identity with the archived Splunkbase app and
  request reinstatement/update through the owner workflow when ready.
- Publish only after the runtime matrix and browser evidence pass. Record the
  package hash, versions tested, remaining risks, and rollback package.

References: [Splunk calculated fields](https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.2/calculated-fields/about-calculated-fields),
[AppInspect CLI](https://dev.splunk.com/enterprise/reference/appinspect/appinspectcliref),
[Sysmon event documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon),
[Splunk savedsearches.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.0-configuration-file-reference/savedsearches.conf).
