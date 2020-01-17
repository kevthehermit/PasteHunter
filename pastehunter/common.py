import json
import logging
import os.path

logger = logging.getLogger('pastehunter')
home = os.path.expanduser("~")

# Parse the config file in to a dict
def parse_config():
    conf = None
    settings_file = os.path.join(home, ".config", "pastehunter.json")

    if os.path.exists(settings_file):
        conf_file = settings_file
    else:
        #ToDo: Copy base settings to the settings file
        conf_file = None

    if conf_file:
        try:
            with open(conf_file, 'r') as read_conf:
                conf = json.load(read_conf)
        except Exception as e:
            logger.error("Unable to parse config file: {0}".format(e))
    else:
        logger.error("Unable to read config file '~/.config/pastehunter.json'")

    return conf
