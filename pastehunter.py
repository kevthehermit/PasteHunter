#!/usr/bin/python3

import os
import sys
import yara
import hashlib
import requests
import datetime
from common import parse_config
from outputs import elastic_output, json_output, csv_output, syslog_output, smtp_output

print("Reading Configs")
# Parse the config file
conf = parse_config()

# populate vars from config
paste_limit = conf['pastebin']['paste_limit']
api_scrape = conf['pastebin']['api_scrape']
api_raw = conf['pastebin']['api_raw']
rule_path = conf['yara']['rule_path']

print("Configure Outputs")
# configure outputs
outputs = []
if conf['elastic_output']['enabled'] == 'True':
    es = elastic_output.ElasticOutput()
    outputs.append(es)

if conf['json_output']['enabled'] == 'True':
    js = json_output.JsonOutput()
    outputs.append(js)

if conf['csv_output']['enabled'] == 'True':
    csv = csv_output.CSVOutput()
    outputs.append(csv)

if conf['syslog_output']['enabled'] == 'True':
    syslog = syslog_output.SyslogOutput()
    outputs.append(syslog)

if conf['smtp_output']['enabled'] == 'True':
    smtp = smtp_output.SMTPOutput()
    outputs.append(smtp)

# Do we need to store all pastes, irrespective of Yara rule matches ?
if conf['pastebin']['store_all'] == 'True':
    store_all = True


def yara_index(rule_path):
    index_file = os.path.join(rule_path, 'index.yar')
    with open(index_file, 'w') as yar:
        for filename in os.listdir('YaraRules'):
            if filename.endswith('.yar') and filename != 'index.yar':
                include = 'include "{0}"\n'.format(filename)
                yar.write(include)


print("Compile Yara Rules")
try:
    # Update the yara rules index
    yara_index(rule_path)
    # Compile the yara rules we will use to match pastes
    index_file = os.path.join(rule_path, 'index.yar')
    rules = yara.compile(index_file)
except Exception as e:
    print("Unable to Create Yara index: ", e)
    sys.exit()

print("Connecting to Pastebin")
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


print("Processing Results")
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

    # get raw paste and hash them
    raw_paste_uri = paste['scrape_url']
    raw_paste_data = requests.get(raw_paste_uri).text

    # Process the paste data here

    try:
        # Scan with yara
        matches = rules.match(data=raw_paste_data)
    except Exception as e:
        print("Unable to scan raw paste : {0} - {1}".format(paste['key'], e))
        continue

    results = []
    for match in matches:
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

    # If we have a result add some meta data and send to storage
    # If results is empty, ie no match, and store_all is True,
    # then append "no_match" to results. This will then force output.

    if store_all is True:
        if len(results) == 0:
            results.append('no_match')

    if len(results) > 0:
        encoded_paste_data = raw_paste_data.encode('utf-8')
        md5 = hashlib.md5(encoded_paste_data).hexdigest()
        sha256 = hashlib.sha256(encoded_paste_data).hexdigest()
        paste_data['MD5'] = md5
        paste_data['SHA256'] = sha256
        paste_data['raw_paste'] = raw_paste_data
        paste_data['YaraRule'] = results
        for output in outputs:
            output.store_paste(paste_data)
        store_count += 1

print("Saved {0} Pastes".format(store_count))
# Store paste ids for next check
with open('paste_history.tmp', 'w')as old:
    old.write(paste_ids)
