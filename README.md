# PasteHunter
Scan pastebin pastes with a collection of yara rules.

# PreReqs

You need a Pro account on pastebin that has access to the scraping API.
https://pastebin.com/api_scraping_faq

* Yara 
* Python3
* Elastic Search Kibana optional

# Install.

## Elastic Search
https://www.elastic.co/guide/en/elasticsearch/reference/current/deb.html

## Kibana
https://www.elastic.co/guide/en/kibana/current/deb.html

## Yara
https://yara.readthedocs.io/en/v3.6.0/gettingstarted.html#compiling-and-installing-yara

Don't forget the python bindings
```pip install yara-python```

If you have yara errors check the installed version numbers for yara and yara-python match the lastest versions.


## This little app
git clone https://github.com/kevthehermit/pastehunter

# Configure

copy settings.conf.sample to settings.conf
populate the details.
For the scraping API you need to whitelist your IP on pastebin. No API key is required. See the link above

# Running

This needs python 3 as per the prereqs. 
You can run it on its own with ```python3 pastehunter.py```

Or you can set a cronjob to run this script every two minutes with a pastelimit of 200

```
localadmin@pastebin:~/pastehunter$ cat /etc/cron.d/pastehunter
# Run every 5 minutes
*/2 * * * *   localadmin  cd /home/localadmin/pastehunter && python3 pastehunter.py >> /home/localadmin/pastehunter/cronlog.txt
localadmin@pastebin:~/pastehunter$
```