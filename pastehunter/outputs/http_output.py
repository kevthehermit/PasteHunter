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
        self.http_headers = config['outputs']['http_output']['headers']
        self.http_auth = config['outputs']['http_output']['http_auth']
        self.http_user = config['outputs']['http_output']['http_user']
        self.http_password = config['outputs']['http_output']['http_password']
        self.ignore_fields = config['outputs']['http_output']['ignore_fields']
        self.timezone = config['outputs']['http_output']['timezone']

        if self.endpoint_url == '':
            logging.error("HTTP endpoint not configured")
            self.valid = False

    def store_paste(self, paste_data):
        if self.valid:

            json_data = paste_data

            for field in self.ignore_fields:
                del json_data[field]

            json_data['@timestamp'] += self.timezone

            if self.http_auth:
                req = requests.post(self.endpoint_url, headers=self.http_headers, json=json_data, auth=(self.http_user, self.http_password))
            else:
                req = requests.post(self.endpoint_url, headers=self.http_headers, data=json_data)

            if req.status_code == 200 or req.status_code == 201:
                logger.debug("Paste sent to HTTP endpoint")
            else:
                logger.error("Failed to post to HTTP endpoint {0}".format(req.status_code))
