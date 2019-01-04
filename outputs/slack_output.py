import os
import datetime
import json
import logging
import requests
from common import parse_config

logger = logging.getLogger('pastehunter')

config = parse_config()


class SlackOutput():
    def __init__(self):
        self.valid = True
        self.webhook_url = config['outputs']['slack_output']['webhook_url']
        self.accepted_rules = config['outputs']['slack_output']['rule_list']

        if self.webhook_url == '':
            logging.error("Slack Webhook not configured")
            self.valid = False
        if self.webhook_url == '':
            logging.error("No Rules configured to alert")

    def store_paste(self, paste_data):
        if self.valid:
            send = False

            for rule in self.accepted_rules:
                if rule in paste_data['YaraRule']:
                    send = True

            if send:
                json_data = {
                    "text": "Pastehunter alert!",
                    "attachments": [
                        {
                            "fallback": "Plan a vacation",
                            "author_name": "PasteHunter",
                            "title": "Paste ID {0}".format(paste_data['pasteid']),
                            "text": "Yara Rule {0} Found on {1}".format(paste_data['YaraRule'], paste_data['pastesite'])
                        }
                    ]
                }

                req = requests.post(self.webhook_url, json=json_data)
                if req.status_code == 200 and req.text == 'ok':
                    logger.debug("Paste sent to slack")
                else:
                    logger.error(
                        "Failed to post to slack Status Code {0}".format(req.status_code))
