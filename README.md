# Sysmon App for Splunk

Dashboards, reports, and investigation searches for Windows Sysmon telemetry.
Joint project by @jarrettp and @m_haggis, with contributions from Gibin John
(beahunt3r) and Vineet Bhatia (threathunting).

**Maintenance candidate:** this checkout is `2.1.0-dev.1`, not a published release.
The [Splunkbase listing](https://splunkbase.splunk.com/app/3544) is archived and
lists version 2.0.0. See [the maintenance review](docs/maintenance-review.md) for
PR/issue decisions and validation limits.

## Contents

- 11 navigable dashboards for Sysmon health, processes, network connections,
  file creation, registry activity, and investigation; one legacy overview view.
- 77 saved searches, including 25 with schedules enabled in the shipped defaults.

The searches are investigation starting points. Review schedules, time windows,
permissions, and local exclusions before production use. Historical IOC names
and ATT&CK IDs are not a claim of current, comprehensive detection coverage.

## Setup

### 1. Collect Sysmon events

Install [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
and choose a configuration appropriate to your environment. Run as administrator:

```powershell
sysmon64.exe -accepteula -i C:\Config\sysmonconfig-export.xml
# Update an existing installation:
sysmon64.exe -c C:\Config\sysmonconfig-export.xml
```

Events are available in **Applications and Services Logs → Microsoft → Windows →
Sysmon → Operational**. Network connection events (ID 3) are disabled by default;
enable the relevant event collection in your Sysmon configuration to populate
network panels. Hash-based panels require MD5 collection and extraction; Sysmon
can collect several hash algorithms. Example configurations are available in
[sysmon-dfir](https://github.com/MHaggis/sysmon-dfir).

Install and configure the
[Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709) using the installation instructions linked from its Splunkbase listing.
The add-on collects/parses events; this visualization app does not collect them.
Ensure its search-time extractions are available on your search head. Avoid
collecting the same channel through duplicate inputs.

The old [Microsoft Sysmon Add-on](https://splunkbase.splunk.com/app/1914) is archived.
Some older installations expose different field names. This candidate includes
compatibility fields, but does not claim that every historical add-on/version
has been runtime-tested.

### 2. Verify ingestion and index access

In Search, replace `YOUR_INDEX` with the index containing your Sysmon events:

```spl
index=YOUR_INDEX earliest=-24h latest=now
| stats count by index source sourcetype
```

Check that your role can search that index. An app does not grant index access,
and this app does not require an index named `threathunting`. Ask your Splunk
administrator to configure the appropriate role/index access if needed.

### 3. Install this app on the search head and configure the macro

Use your deployment's normal app installation process. To build a clean local
package from this repository:

```sh
python3 scripts/package_app.py
```

In **Settings → Advanced search → Search macros**, find `sysmon` in this app's
context. Set its definition to your index while retaining the parenthesized
event selector. Save overrides in `local/macros.conf` or through Splunk Web;
editing `default/` will be overwritten by upgrades. Without an explicit index,
Splunk searches only your role's default indexes, which may not include Sysmon.

```ini
[sysmon]
definition = index=YOUR_INDEX (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" OR source="WinEventLog:Microsoft-Windows-Sysmon/Operational" OR sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" OR sourcetype="WinEventLog:Sysmon")
iseval = 0
```

The source selector covers the current add-on's Sysmon channel even when its
sourcetype is the generic `XmlWinEventLog`. The three explicit Sysmon sourcetypes
retain older/custom configurations. Do **not** select all `XmlWinEventLog` events
without restricting the source/channel: that also includes other Windows logs.
The macro is an event selector, not a pipeline.

### 4. Verify fields in this app's Search page

```spl
`sysmon` earliest=-24h latest=now
| table _time source sourcetype EventCode Computer ComputerName Image CommandLine
    sysmon_computer sysmon_process_name sysmon_process_path sysmon_user
    sysmon_dest_host sysmon_dest_ip sysmon_dest_port sysmon_protocol
```

This app adds `sysmon_*` fields at search time, scoped to its app context. It
preserves raw and CIM fields. `sysmon_process_name` is the executable basename;
`sysmon_process_path` is the full `Image` path. `sysmon_computer` uses the event's
`Computer` or `ComputerName`, not the collector's `host`. Network destination
display falls back to an IP when the event has no hostname. See the
[field contract and runtime checks](docs/validation.md).

Open a dashboard, choose a time range, and click **Submit** after changing text
filters. Defaults run on initial load; time-picker changes trigger searches.

## No data or incomplete panels

1. If the index search returns nothing, check collection, index permissions, and
   the time range before changing dashboard searches.
2. If the index search works but `` `sysmon` `` is empty, compare the observed
   source/sourcetype with the macro. Existing `local/macros.conf` overrides still
   win after an app upgrade.
3. If the macro returns events but `EventCode`, `Image`, or event-computer fields
   are absent, check the installed add-on's extraction in this search context.
4. If only particular panels are empty, check the required event IDs and MD5
   configuration. Absence of matching data is not proof that an attack cannot
   occur.
5. Existing local dashboard/saved-search overrides may hide shipped fixes.
   Compare them before deployment; preserve your local tuning.

## Development and release checks

```sh
python3 -m unittest discover -s tests -v
python3 scripts/validate_app.py
python3 scripts/package_app.py
# Install AppInspect in a separate virtual environment, then:
splunk-appinspect inspect .context/dist/sysmon-splunk-app.tgz --mode precert
```

Static checks and AppInspect do not execute SPL or establish Splunk Cloud
approval. Follow [validation.md](docs/validation.md) for the real add-on,
search-job, browser, upgrade, and release gates.

## Credits and license

Thanks to HVSoftware for PRs #15–#18, which highlighted the compatibility issues
addressed in this maintenance work. The corrections preserve compatibility
rather than applying those field replacements verbatim.

Source code is distributed under the [MIT license](LICENSE).
