import json
import logging


# Parse the config file in to a dict
def parse_config():
    conf_file = 'settings.json'
    conf = None
    try:
        with open(conf_file, 'r') as read_conf:
            conf = json.load(read_conf)
    except Exception as e:
        logging.error("Unable to parse config file: {0}".format(e))

    return conf
