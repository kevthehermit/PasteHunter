import logging
import requests
import json
from common import parse_config

logger = logging.getLogger('pastehunter')

config = parse_config()

class HttpOutput():
    def __init__(self):
        self.valid = True
        self.endpoint_url = config['outputs']['http_output']['endpoint_url']
        self.http_auth = config['outputs']['http_output']['http_auth']
        self.http_user = config['outputs']['http_output']['http_user']
        self.http_password = config['outputs']['http_output']['http_password']

        if self.endpoint_url == '':
            logging.error("HTTP endpoint not configured")
            self.valid = False

    def store_paste(self, paste_data):
        if self.valid:
            
            json_data = paste_data
            del json_data['raw_paste']
            json_data['@timestamp'] += 'Z'
            if self.http_password:
                #req = requests.post(self.endpoint_url, headers=headers, data=json_data, auth=(self.http_user, self.http_password))
                req = requests.post(self.endpoint_url, json=json_data, auth=(self.http_user, self.http_password))
            else:
                #req = requests.post(self.endpoint_url, headers=headers, data=json_data)
                req = requests.post(self.endpoint_url, json=json_data)

            if req.status_code == 200 and req.text == 'ok':
                logger.debug("Paste sent to HTTP endpoint")
            else:
                logger.error("Failed to post to HTTP endpoint {0}".format(req.status_code))
