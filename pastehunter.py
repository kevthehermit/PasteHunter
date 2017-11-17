#!/usr/bin/python3

import os
import sys
import yara
import json
import hashlib
import requests
from time import sleep
from common import parse_config
from outputs import elastic_output, json_output, csv_output, syslog_output, smtp_output
from queue import Queue
import threading
import importlib
import logging

lock = threading.Lock()

# Set some logging options
logging.basicConfig(level=logging.INFO)
logging.getLogger('requests').setLevel(logging.ERROR)

logging.info("Reading Configs")
# Parse the config file
conf = parse_config()

# populate vars from config
api_raw = conf['pastebin']['api_raw']
rule_path = conf['yara']['rule_path']
blacklist = conf['yara']['blacklist']
store_all = conf['pastebin']['store_all']
input_list = conf['inputs']['inputs']

logging.info("Configure Outputs")
# configure outputs
outputs = []
if conf['elastic_output']['enabled']:
    es = elastic_output.ElasticOutput()
    outputs.append(es)
    logging.info("Elastic Output Enabled")

if conf['json_output']['enabled']:
    js = json_output.JsonOutput()
    outputs.append(js)
    logging.info("Json Output Enabled")

if conf['csv_output']['enabled']:
    csv = csv_output.CSVOutput()
    outputs.append(csv)
    logging.info("CSV Output Enabled")

if conf['syslog_output']['enabled']:
    syslog = syslog_output.SyslogOutput()
    outputs.append(syslog)
    logging.info("Syslog Output Enabled")

if conf['smtp_output']['enabled']:
    smtp = smtp_output.SMTPOutput()
    outputs.append(smtp)
    logging.info("SMTP Output Enabled")


def yara_index(rule_path):
    index_file = os.path.join(rule_path, 'index.yar')
    with open(index_file, 'w') as yar:
        for filename in os.listdir('YaraRules'):
            if filename.endswith('.yar') and filename != 'index.yar':
                include = 'include "{0}"\n'.format(filename)
                yar.write(include)


def paste_scanner():
    # Get a paste URI from the Queue
    # Fetch the raw paste
    # scan the Paste
    # Store the Paste
    while True:
        paste_data = q.get()
        logging.info("Found New {0} paste {1}".format(paste_data['pastesite'], paste_data['pasteid']))
        # get raw paste and hash them
        raw_paste_uri = paste_data['scrape_url']
        raw_paste_data = requests.get(raw_paste_uri).text
        # Process the paste data here

        try:
            # Scan with yara
            matches = rules.match(data=raw_paste_data)
        except Exception as e:
            logging.error("Unable to scan raw paste : {0} - {1}".format(paste_data['pasteid'], e))
            continue

        results = []
        for match in matches:
            # For keywords get the word from the matched string
            if match.rule == 'core_keywords' or match.rule == 'custom_keywords':
                for s in match.strings:
                    rule_match = s[1].lstrip('$')
                    if rule_match not in results:
                        results.append(rule_match)
                results.append(str(match.rule))

            # But a break in here for the base64. Will use it later.
            elif match.rule.startswith('b64'):
                results.append(match.rule)

            # Else use the rule name
            else:
                results.append(match.rule)

        # Blacklist Check
        # If any of the blacklist rules appear then empty the result set
        if blacklist and 'blacklist' in results:
            results = []
            logging.info("Blacklisted {0} paste {1}".format(paste_data['pastesite'], paste_data['pasteid']))

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

        # Mark Tasks as complete
        q.task_done()


if __name__ == "__main__":
    logging.info("Compile Yara Rules")
    try:
        # Update the yara rules index
        yara_index(rule_path)
        # Compile the yara rules we will use to match pastes
        index_file = os.path.join(rule_path, 'index.yar')
        rules = yara.compile(index_file)
    except Exception as e:
        print("Unable to Create Yara index: ", e)
        sys.exit()

    # Create Queue to hold paste URI's
    q = Queue()

    # Threads
    for i in range(5):
        t = threading.Thread(target=paste_scanner)
        t.daemon = True
        t.start()

    # Now Fill the Queue
    try:
        while True:
            # Paste History
            logging.info("Populating Queue")
            if os.path.exists('paste_history.tmp'):
                with open('paste_history.tmp') as json_file:
                    paste_history = json.load(json_file)
            else:
                paste_history = {}

            for input_name in input_list.split(','):
                if input_name in paste_history:
                    input_history = paste_history[input_name]
                else:
                    input_history = []

                import_name = 'inputs.{0}'.format(input_name)
                i = importlib.import_module(import_name)
                # Get list of recent pastes
                paste_list, history = i.recent_pastes(conf, input_history)
                for paste in paste_list:
                    q.put(paste)
                paste_history[input_name] = history

            # Write History
            with open('paste_history.tmp', 'w') as outfile:
                json.dump(paste_history, outfile)

            # Flush the list
            q.join()

            # Slow it down a little
            logging.info("Sleeping for 10 Seconds")
            sleep(10)

    except KeyboardInterrupt:
        logging.info("Stopping Threads")
