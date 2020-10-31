import json
import logging
import os.path

logger = logging.getLogger('pastehunter')
home = os.path.expanduser("~")

BASE62_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
BASE_LOOKUP = dict((c, i) for i, c in enumerate(BASE62_CHARS))
BASE_LEN = len(BASE62_CHARS)

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


# Most of this was pulled from https://stackoverflow.com/a/2549514
def base62_decode(input: str) -> int:
    length = len(BASE_LOOKUP)
    ret = 0
    for i, c in enumerate(input[::-1]):
        ret += (length ** i) * BASE_LOOKUP[c]

    return ret


def base62_encode(integer) -> str:
    if integer == 0:
        return BASE62_CHARS[0]

    ret = ''
    while integer != 0:
        ret = BASE62_CHARS[integer % BASE_LEN] + ret
        integer //= BASE_LEN

    return ret
