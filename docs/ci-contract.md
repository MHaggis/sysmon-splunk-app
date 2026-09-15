# CI acceptance contract

This follow-up adds automated checks to maintenance PR #19. It does not merge
the PR, publish a release, or replace the Splunk runtime acceptance matrix.

Assurance: **A3 for the CI execution boundary** because workflows execute
contributor code and produce candidate packages. The application remains an A2
maintenance change. An independent review must inspect workflow permissions,
untrusted PR execution, dependency pins, and failure handling before pushing.

| ID | Behavior | Evidence |
| --- | --- | --- |
| CI-01 | PRs and master pushes run existing regression/config/XML checks and construct the candidate package. | Local checks and a successful GitHub-hosted run for the PR head; record the exact tested merge commit and package hash. |
| CI-02 | AppInspect runs on that package; failures, errors, future failures, unknown results and invalid/empty reports fail CI. | Positive/negative report-gate unit tests and the real AppInspect report. |
| CI-03 | Known warnings remain visible; new warnings/skips require deliberate review. | Versioned, narrowly scoped baseline and gate regression tests. |
| CI-04 | Reviewers can download the exact candidate and diagnostic evidence, including failed-run evidence. | Workflow artifact with package, checksum, logs and JSON report; successful artifact retrieval. |
| CI-05 | Fork PR code receives no repository secrets, write-capable repository token, persistent Git credentials, or deployment access. | Independent workflow review; pull_request event, contents:read, pinned actions, hosted ephemeral runner. |

Use a bounded timeout and cancel obsolete runs. Pin AppInspect and third-party
action revisions. Keep dependency updates reviewable. Never use pull_request_target
to execute PR code, never auto-merge or publish from this validation workflow, and
never turn an absent report into a green check. Runtime/Cloud evidence remains a
separate gate documented in [validation.md](validation.md).
