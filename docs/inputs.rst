Inputs
======

This page details all the configuration options per input. 

There are a few generic options for each input. 
- **enabled**: This turns the input on and off. 
- **store_all**: ignore the only store on matching rule.
- **module**: This is used internally by pastehunter.

Pastebin
------------
To use the pastebin API you need an API key. These need to be purchased and are almost always on some sort of offer!
https://pastebin.com/pro The API uses your IP to authenticate instead of a key. You will need to whitelist your IP at https://pastebin.com/api_scraping_faq

- **api_scrape**: The URL endpoint for the list of recent paste ids.
- **api_raw**: The URL endpoint for the raw paste.
- **paste_limit**: How many pasteids to fetch from the recent list. 
- **store_all**: Store all pastes regardless of a rule match.

Github Gists
---------------
Github has an API that can be used at no cost to query recent gists. There are two options here. 

- Without an access key - You will have a low rate limit.
- With an access key - You will have a higher rate limit. 

The unauthenticated option is not suitable for pastehunter running full time. 
To create your key visit https://github.com/settings/tokens

*YOU DO NOT NEED TO GIVE IT ANY ACCESS PERMISSIONS*

- **api_token**: The token you generated.
- **api_limit**: Rate limit to prevent being blocked.
- **store_all**: Store all pastes regardless of a rule match.
- **user_blacklist**: Do not process gists created by these usernames.
- **file_blacklist**: Do not process gists that match these filenames.

Github Activity
---------------
Github's activity feed is a list of public changes made. We specifically filter on commits. It can be accessed in a similar manner to gists:

- Without an access key - You will have a low rate limit.
- With an access key - You will have a higher rate limit.

Again, the unauthenticated option is not suitable for pastehunter running full time, particularly if you're also running the gist
input. However, the same token may be used for both inputs.

- **api_token**: The token you generated.
- **api_limit**: Rate limit to prevent being blocked.
- **store_all**: Store all pastes regardless of a rule match.
- **user_blacklist**: Do not process gists created by these usernames.
- **ignore_bots**: Ignore users with ``[bot]`` in their username (only actual bots can do this)
- **file_blacklist**: Do not process gists that match these filenames. Supports glob syntax.

Slexy
---------

Slexy has some heavy rate limits (30 requests per 30 seconds), but may still return interesting results.

- **store_all**: Store all pastes regardless of a rule match.
- **api_scrape**: The URL endpoint for the list of recent pastes.
- **api_raw**: The URL endpoint for the raw paste.
- **api_view**: The URL enpoint to view the paste.

ix.io
---------

ix.io is a smaller site used primarily for console/command line pastes.

- **store_all**: Store all pastes regardless of a rule match.

StackExchange
-------------

The same API is used to query them all. Similar to github there is a public API which has a reduced rate limit 
or an App API which has a higher cap. There is a cap on 10,000 requests per day per IP, so pulling all would be impractical. 
Generate a key at https://stackapps.com/.

There are over 170 exchanges that form stackexchange. The following list is the most likly to expose privldidged information.

* stackoverflow
* serverfault
* superuser
* webapps
* webmasters
* dba

- **site_list**: List of site shorttitles that will be scraped. 
- **api_key**: API App key as generated above.
- **store_filter**: This is the stackexchange filter that determines what fields are returned. It must contain the body element.
- **pagesize**: How many questions to pull from the latest list. 
- **store_all**: Store all pastes regardless of a rule match.