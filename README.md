# Sysmon Splunk app

Credits to @jarrettp and @m_haggis for providing the base fork of this config. Incremental changes have been made to meet my specific needs. Feel free to use or send a pull request.


# Setup

Deploy the [Sysmon-TA](https://splunkbase.splunk.com/app/1914/)
~~~~
Download and deploy this app to your Splunk Search Head.
~~~~
A macro is used for all saved searches, you will need to modify it for your environment to ensure the proper Sysmon sourcetype/index is searched.
Macros: Settings --> Advanced Search --> Search Macros. Edit to your environment
Default - sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
