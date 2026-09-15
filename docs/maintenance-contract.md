# Maintenance update contract

Review date: 2026-09-15. Baseline: `5c6e54e869f2b536c482c3534a16835725b44386` (`origin/master`).

## Intent and scope

Make the existing Sysmon app understandable to install and maintain, review all
four open pull requests and five open issues, and correct demonstrated
compatibility and search defects. Preserve attribution and existing saved-search
identities. The maintainer has authorized consolidating this work into a draft
pull request, including pushing the review branch and linking the original
contributions and issues. Merging, release publication, and Cloud approval remain
outside this phase.

Assurance: **A2** for dashboard and search behavior. This app presents telemetry
and detection candidates; it does not enforce endpoint security. Publication is
a separate release decision requiring independent review and runtime evidence.

## Behaviors and acceptance evidence

| ID | User-visible behavior | Required evidence |
| --- | --- | --- |
| SM-01 | The event selector covers documented Sysmon formats and remains locally configurable. | Authoritative add-on configuration; selector regression check; runtime counts by index/source/sourcetype. |
| SM-02 | Host, executable, and network fields retain their meaning across supported input formats. | Exact PR review; field contract; fixtures/queries including full Windows paths and missing hostnames; real add-on extraction check. |
| SM-03 | Dashboards initialize, respect inputs, and use the correct Sysmon event IDs. | XML and token checks; independent review; authenticated browser, console and search-job evidence before release. |
| SM-04 | Corrected saved searches have bounded time windows and express their stated conditions. | Focused regression checks; positive/negative SPL cases on Splunk before release. |
| SM-05 | The app has valid package metadata and current Simple XML declarations. | Repeatable package construction and Splunk AppInspect results. |
| SM-06 | Every open PR and issue receives an evidence-backed maintainer disposition. | Review report with immutable PR heads, source links, draft replies and explicit unresolved items. |

## Integration seam and constraints

The real seam is Sysmon event generation, Windows Event Log collection, the
installed Splunk add-on's extraction/normalization, and this app's search context.
A field-name replacement alone cannot prove that seam. Native `Image` is a path;
a normalized `process` field is not a reliable substitute for that path or its
basename. Preserve the distinction. Existing `local/` settings override shipped
defaults and must be checked during upgrades.

## Stop rules

- Make local corrections only where code and primary documentation support them.
- Record environment-dependent behavior and ambiguous detection intent instead
  of guessing an operational guarantee.
- Static checks and AppInspect do not establish detection efficacy, successful
  extraction, dashboard rendering, or Splunk Cloud approval.
- Report passed, failed and skipped evidence; block publication when runtime or
  release evidence is missing.
