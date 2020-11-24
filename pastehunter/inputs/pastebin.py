from typing import Any, Dict, Union, Optional

import requests
import logging
from datetime import datetime

from pastehunter.inputs.base_input import BasePasteSite

logger = logging.getLogger('pastehunter')


class PastebinPasteSite(BasePasteSite):

    def __init__(self, conf):
        self.conf = conf

    def remap_raw_item(self, raw_item: Dict) -> Dict[str, Any]:
        # Create a new paste dict for us to normalize
        pid = self.get_paste_id(raw_item)
        paste_data = raw_item
        paste_data['filename'] = pid
        paste_data['confname'] = 'pastebin'
        paste_data['pasteid'] = pid
        paste_data['pastesite'] = 'pastebin.com'
        # Add a date field that kibana will map
        date = datetime.utcfromtimestamp(float(paste_data['date'])).isoformat()
        paste_data['@timestamp'] = date
        return paste_data

    def make_request(self, url: str, timeout: Optional[int] = 10, headers: Optional[Dict[str, Any]] = None):
        paste_list_request = super(PastebinPasteSite, self).make_request(url, timeout, headers)

        # Check to see if our IP is whitelisted or not.
        if 'DOES NOT HAVE ACCESS' in paste_list_request.text:
            logger.error("Your IP is not whitelisted visits 'https://pastebin.com/doc_scraping_api'")
            return None
        return paste_list_request

    def get_paste_for_id(self, paste_id: Any) -> str:
        pass

    def get_paste_id(self, paste_obj: Dict[str, Any]) -> Union[str, int]:
        return paste_obj['key']

    def get_recent_items(self, input_history):
        paste_limit = self.conf['inputs']['pastebin']['paste_limit']
        api_scrape = self.conf['inputs']['pastebin']['api_scrape']

        history = []
        paste_list = []
        try:
            # Create the API uri
            scrape_uri = '{0}?limit={1}'.format(api_scrape, paste_limit)
            # Get some pastes and convert to json
            # Get last 'paste_limit' pastes

            paste_list_request = self.make_request(scrape_uri)

            # IP not whitelisted
            if not paste_list_request:
                return [], []

            paste_list_json = paste_list_request.json()

            for paste in paste_list_json:
                pid = self.get_paste_id(paste)
                # Track paste ids to prevent dupes
                history.append(pid)
                if pid in input_history:
                    continue

                paste_data = self.remap_raw_item(paste)
                paste_list.append(paste_data)

            return paste_list, history

        except Exception as e:
            logger.error("Unable to parse paste results: {0}".format(e))
            return paste_list, history


def recent_pastes(conf, input_history):
    site = PastebinPasteSite(conf)
    # populate vars from config
    return site.get_recent_items(input_history)



