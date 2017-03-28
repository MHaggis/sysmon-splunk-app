# Sysmon Splunk app

This is combined Splunk App effort between @jarrettp and @m_haggis.

# Setup

Deploy the [Sysmon-TA](https://splunkbase.splunk.com/app/1914/)

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

I recommend going with @SwiftOnSecurity latest config located here:

https://github.com/SwiftOnSecurity/sysmon-config

Additionally, other example Sysmon configs may be found [here](https://github.com/MHaggis/sysmon-dfir)

# Contributing

PLEASE CONTRIBUTE AND SHARE!
