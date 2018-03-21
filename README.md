# Sysmon Splunk app

This is combined Splunk App effort between @jarrettp and @m_haggis.

# Joint Contributor Credits

* Gibin John (beahunt3r)
* Vineet Bhatia (threathunting)


Current Dashboards:  
- Sysmon Overview - Shows basic overview and usage for Sysmon events.  
- Investigator - Allows searching of events for specific hosts, users.  
- Network Overview  
- File Creation Overview  
- Process Overview  
- Suspicious Indicators - Collection of some known IOC
- Registry Overview
- Network Connections
- Process Finder - Helps find unique hash values based on percentage
- Process Timeline - Uses LogonGuid to map timeline of processes. Allows clicking for drilldown.

Reports:
- Over 40+ reports

Alerts:
- 19 Pre-built alerts

# Setup

Deploy [Sysmon-TA](https://splunkbase.splunk.com/app/1914/)

Download and deploy this app to your Splunk Search Head.

A macro is used for all saved searches, you will need to modify it for your environment to ensure the proper Sysmon sourcetype/index is searched.

Macros: Settings --> Advanced Search --> Search Macros. Edit to your environment

Default - sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"

Thats it.


# Install Sysmon

### Install ###

Run with administrator rights
~~~~
sysmon.exe -accepteula -i sysmonconfig-export.xml
~~~~

### Update existing configuration ###

Run with administrator rights

sysmon.exe -c sysmonconfig-export.xml

Upon installation, Sysmon will begin logging events to the operational event log “C:\Windows\System32\ winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx”.

## Sysmon configuration ##

Sysmon resources and example configuration files may be found [here](https://github.com/MHaggis/sysmon-dfir)
