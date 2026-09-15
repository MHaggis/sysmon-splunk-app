# Maintenance candidate evidence

Review baseline: `5c6e54e869f2b536c482c3534a16835725b44386`.
Candidate: `2.1.0-dev.1`, build `2026091501`.

## Independent review

Four agents separately reviewed the PR field semantics, issues and setup,
dashboards, and all 77 saved searches. The implementation was then reviewed by
a separate Sol review pass. Findings corrected during that pass included
full-path matching, timeline input/detail synchronization, misleading chart
limits, and a filename regex escaping defect. The filename panel now reuses the
normalized basename instead of introducing another regex.

Final static disposition: **READY_WITH_RISKS for test installation**, with no
remaining newly introduced static behavior blockers found. This does not approve
the inherited detection library or establish compatibility through execution.
The [maintenance review](maintenance-review.md) lists known legacy defects.

## Checks performed

| Check | Result | What it does not establish |
| --- | --- | --- |
| `python3 -m unittest discover -s tests -v` | 15 tests passed | Does not execute SPL. |
| `python3 scripts/validate_app.py` | 12 views, 77 saved searches, 120 query definitions; passed | Not a complete SPL parser or runtime. |
| `xmllint --noout default/data/ui/views/*.xml default/data/ui/nav/default.xml` | Passed | Does not render dashboards or exercise tokens. |
| `git -c core.whitespace=cr-at-eol diff --check` | Passed | Retains existing CRLF line endings; default Git whitespace checking flags those line endings. |
| Splunk AppInspect CLI 4.3.1, `--mode precert` | 102 successes, 0 failures, 0 errors, 0 future failures, 2 warnings, 1 skipped, 147 not applicable | Does not grant Cloud approval or execute searches. |

AppInspect warnings are retained deliberately:

- The private-app heuristic flags `check_for_updates=true`. This is an existing
  public Splunkbase app; its update-check setting is explicit.
- Two legacy sourcetype names contain `/`. They match existing Sysmon inputs;
  renaming them to suppress a warning would break compatibility.

The skipped check concerns the absent optional `app.manifest`. Review these
items again in the final target-specific publication workflow.

The package builder is deterministic and excludes `.context/`, credentials,
local overrides, Git, tests, and scripts. Exact package hashes and full tool
outputs are retained in the local `.context/review/` evidence. Reproduce the
checks from [validation.md](validation.md); the draft PR records the candidate
package hash associated with its validation run.

## Required before merge/release

- Execute the changed SPL against the intended Splunk and Sysmon TA versions,
  including native-field extraction and app-context base-search filters.
- Exercise authenticated dashboards, input changes, drilldowns and search jobs;
  inspect browser console/network errors and capture visual evidence.
- Validate scheduled-search positive/negative cases, time windows, and load.
- Confirm upgrade behavior with existing `local/` overrides.
- Complete Cloud AppInspect API/vetting if claiming Cloud compatibility, and
  separately handle the archived Splunkbase listing.

**Release status: BLOCKED.** No Splunk runtime or target deployment was available
for the original review. Read-only SPL fixtures and the acceptance matrix are
prepared; missing runtime evidence is explicitly not counted as a pass.
