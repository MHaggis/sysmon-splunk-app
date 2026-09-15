# Continuous integration

The **Sysmon app CI** workflow runs on pull requests to `master`, pushes to
`master`, and manual dispatch (once the workflow exists on the default branch).
Draft PRs are checked too. It does not merge PRs or publish releases.

## What runs

1. Regression tests, including corrupted/missing AppInspect-report cases.
2. Config checks, XML parsing, and a CRLF-aware whitespace check.
3. Deterministic app packaging and a SHA-256 checksum.
4. AppInspect 4.3.1 on that package, with all checks and all diagnostic messages.
5. A report gate comparing the actual check inventory, findings, and summaries
   with the reviewed [.ci/appinspect-baseline.json](../.ci/appinspect-baseline.json).

The report gate fails for AppInspect failures, errors, future failures, unknown
results, missing/invalid JSON, filtered runs, missing/duplicate checks, summary
mismatches, or any changed warning/skip diagnostics. The two known warnings and
one skipped check remain visible in the job summary. A resolved exception also
requires updating the baseline so a truncated report cannot silently look better.
The AppInspect command must exit successfully as well; the JSON gate does not
override a failed process.

## Evidence

Every run attempts to upload a **static-candidate** artifact containing:

- The candidate `.tgz` and a checksum file.
- The exact tested commit.
- Regression/config and AppInspect logs, the complete JSON report, gate output,
  and AppInspect exit status.
- An explicit statement that Splunk runtime and Cloud approval were not tested.

Artifacts expire after 14 days. Failed runs preserve whatever diagnostic evidence
was produced. Treat PR artifacts as untrusted test candidates; do not promote
them automatically to a release or execute content from them in a privileged job.

For `pull_request`, GitHub checks out its synthetic merge commit by default.
That validates the proposed change combined with the base branch. The artifact's
`tested-commit.txt` and the Actions run identify what was actually checked; it can
differ from the branch head. Push/manual runs identify their own tested commits.

## Execution boundary and dependencies

- GitHub-hosted Ubuntu 24.04 runner, Python 3.12, 15-minute timeout; obsolete runs
  are cancelled.
- Repository token restricted to `contents: read`; checkout does not persist Git
  credentials. No repository secrets, `pull_request_target`, deployment access,
  cache sharing, or automatic merge/release steps.
- GitHub actions are pinned to full commit SHAs. All 21 runtime packages,
  and the two source-build tools are version-pinned and hash-checked.
- `painter` is source-distribution-only. Its hash is pinned and it builds with
  the pinned tools, with build isolation disabled to prevent extra unpinned
  build-tool downloads.
- AppInspect's trusted-library auto-update is disabled for these repeatable
  checks. Current target-specific AppInspect/Cloud vetting is still a release
  requirement; this frozen CI version is not a claim of current Cloud approval.
- Monthly Dependabot groups propose action and Python-dependency updates.
  Updates are reviewed PRs, never automatic merges.

## Reproduce locally

Use a Python 3.12 virtual environment. Install your platform's `libmagic` and
`xmllint` packages before running AppInspect/XML checks.

```sh
python3.12 -m venv .context/ci-venv
.context/ci-venv/bin/python -m pip install --require-hashes --only-binary=:all: -r .ci/build-requirements.txt
.context/ci-venv/bin/python -m pip install --require-hashes --no-build-isolation -r .ci/requirements.txt
.context/ci-venv/bin/python -m unittest discover -s tests -v
python3 scripts/validate_app.py
xmllint --noout default/data/ui/views/*.xml default/data/ui/nav/default.xml
python3 scripts/package_app.py
.context/ci-venv/bin/splunk-appinspect inspect .context/dist/sysmon-splunk-app.tgz --mode precert --max-messages all --skip-trusted-libraries-update --output-file .context/appinspect.json
python3 scripts/check_appinspect.py .context/appinspect.json
```

When updating AppInspect, compare the new check inventory and findings with the
old report, investigate changes, and edit the baseline with an explanation. Do
not regenerate an acceptance baseline blindly from a failing report. Preserve
the fail-closed gate tests.

After the workflow is established, the stable job name **Static checks and
AppInspect** can be made a required check in branch protection. Adding the workflow
does not itself change repository protection settings. A passing check still
does not satisfy the [Splunk runtime validation matrix](validation.md).

References: [GitHub PR workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request),
[GitHub workflow security](https://docs.github.com/en/actions/reference/security/secure-use),
[pip hash-checking mode](https://pip.pypa.io/en/stable/topics/secure-installs/),
[AppInspect CLI](https://dev.splunk.com/enterprise/reference/appinspect/appinspectcliref).
