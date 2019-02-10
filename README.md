# PasteHunter
PasteHunter is a python3 application that is designed to query a collection of sites that host publicliy pasted data. 
For all the pasts it finds it scans the raw contents against a series of yara rules looking for information that can be used 
by an organisation or a researcher.

For setup instructions please see the `official documentation <https://pastehunter.readthedocs.io/en/latest/installation.html>`_

## Supported Inputs
Pastehunter currently has support for the following sites:
 - pastebin.com
 - gist.github.com
 - slexy.org
 - stackexchange # There are about 176! 

## Supported Outputs
Pastehunter supports several output modules:
 - dump to ElasticSearch DB (default).
 - Email alerts (SMTP).
 - Slack Channel notifications.
 - Dump to JSON file.
 - Dump to CSV file.
 - Send to syslog.

For examples of data discovered using pastehunter check out my posts `Using pastehunter <https://techanarchy.net/blog/hunting-pastebin-with-pastehunter>`_ and 
`Pastehunter results <https://techanarchy.net/blog/pastehunter-the-results>`_


