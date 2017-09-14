#!/usr/bin/python3

import os
import sys
import yara
import hashlib
import requests
import datetime
from elasticsearch import Elasticsearch
import configparser


# Parse the config file in to a dict
def parse_config():
    config_dict = {}
    config = configparser.ConfigParser(allow_no_value=True)

    conf_file = 'settings.conf'

    valid = config.read(conf_file)
    if len(valid) > 0:
        config_dict['valid'] = True
        for section in config.sections():
            section_dict = {}
            for key, value in config.items(section):
                section_dict[key] = value
            config_dict[section] = section_dict
    else:
        config_dict['valid'] = False
    return config_dict


def yara_index(rule_path):
    index_file = os.path.join(rule_path, 'index.yar')
    with open(index_file, 'w') as yar:
        for filename in os.listdir('YaraRules'):
            if filename.endswith('.yar') and filename != 'index.yar':
                include = 'include "{0}"\n'.format(filename)
                yar.write(include)


# Parse the config file
conf = parse_config()


# populate vars from config
paste_limit = conf['pastebin']['paste_limit']
api_scrape = conf['pastebin']['api_scrape']
api_raw = conf['pastebin']['api_raw']
es_host = conf['database']['elastic_host']
es_port = conf['database']['elastic_port']
rule_path = conf['yara']['rule_path']


#Set up the database connection
try:
    es = Elasticsearch(es_host, port=es_port)
except Exception as e:
    print("[!] Unable to connect to Elastic Search: ", e)
    sys.exit()

try:
    # Update the yara rules index
    yara_index(rule_path)
    # Compile the yara rules we will use to match pastes
    index_file = os.path.join(rule_path, 'index.yar')
    rules = yara.compile(index_file)
except Exception as e:
    print("Unable to Create Yara index: ", e)
    sys.exit()

try:
    # Create the API uri
    scrape_uri = '{0}?limit={1}'.format(api_scrape, paste_limit)
    # Get some pastes and convert to json
    # Get last 'paste_limit' pastes
    paste_list_request = requests.get(scrape_uri)
    paste_list_json = paste_list_request.json()
except Exception as e:
    print("Unable to parse paste results: ", e)
    sys.exit()


# Iterate the results
store_count = 0
paste_ids = ''
# Get paste ids from last round
if os.path.exists('paste_history.tmp'):
    with open('paste_history.tmp', 'r')as old:
        old_pastes = old.read().split(',')
else:
    old_pastes = []

for paste in paste_list_json:
    # Track paste ids to prevent dupes
    paste_ids += '{0},'.format(paste['key'])
    if paste['key'] in old_pastes:
        print("Already Processed, Skipping")
        continue

    # Create a new paste dict for us to modify
    paste_data = paste

    # Add a date field that kibana will map
    date = datetime.datetime.utcfromtimestamp(float(paste_data['date'])).isoformat()
    paste_data['@timestamp'] = date

    #print("Found paste: {0}".format(paste['key']))
    # get raw paste and hash them
    raw_paste_uri = paste['scrape_url']
    raw_paste_data = requests.get(raw_paste_uri).text

    # Process the paste data here
    paste_data['regex_results'] = []
    paste_data['keywords'] = []

    try:
        # Scan with yara
        matches = rules.match(data=raw_paste_data)
    except Exception as e:
        print("Unable to scan raw paste : {0} - {1}".format(paste['key'], e))
        continue

    results = []
    for match in matches:
        #print(match.strings)
        # For keywords get the word from the matched string
        if match.rule == 'core_keywords' or match.rule == 'custom_keywords':
            for s in match.strings:
                rule_match = s[1].lstrip('$')
                if rule_match not in results:
                    results.append(rule_match)

        # But a break in here for the base64. Will use it later.
        elif match.rule.startswith('b64'):
            results.append(match.rule)

        # Else use the rule name
        else:
            results.append(match.rule)

    # If we have a result send it to ES
    if len(results) > 0:
        encoded_paste_data = raw_paste_data.encode('utf-8')
        md5 = hashlib.md5(encoded_paste_data).hexdigest()
        sha256 = hashlib.sha256(encoded_paste_data).hexdigest()
        paste_data['MD5'] = md5
        paste_data['SHA256'] = sha256
        paste_data['raw_paste'] = raw_paste_data
        paste_data['YaraRule'] = results
        try:
            stored = es.index(index='paste-test', doc_type='paste', id=paste['key'], body=paste_data)
            store_count += 1
            print("Stored: {0}".format(paste['key']))
        except Exception as e:
            print("Unable to store results: {0} - {1}".format(paste['key'], e))

print("Saved {0} Pastes".format(store_count))
# Store paste ids for next check
with open('paste_history.tmp', 'w')as old:
    old.write(paste_ids)
