import logging
import re
from datetime import datetime
from typing import List, Any, Dict, Union, Pattern

from pastehunter.common import base62_decode, base62_encode
from pastehunter.inputs.base_input import BasePasteSite

logger = logging.getLogger('pastehunter')


class IxDotIoSite(BasePasteSite):
    # Yeah, yeah, I know, no regex for HTML parsing...
    # If we end up doing a lot more of this, then maybe we'll use beautifulsoup or something.
    # Capturing groups:
    # 1. Paste ID
    # 2. Timestamp
    _ITEM_ID_RE: Pattern = re.compile('<div class="t">[\\sa-zA-Z0-9]+'
                                         '<a href="/(.*?)">\\[r][^\r\n]+'
                                         '\\s+@ (.*?)[\r\n]')

    def __init__(self, conf):
        self.conf = conf
        self.site = "ix.io"
        url_main = "http://" + self.site
        self.url_recent = url_main + "/user/"
        self.view_pattern = url_main + "/{}/"
        self.raw_pattern = url_main + "/{}"
        self.url = None

    def remap_raw_item(self, raw_item: [str, Dict]) -> Dict[str, Any]:
        pid = raw_item['pid']
        paste_data = {
            # at a
            'filename': str(pid),
            'confname': 'ixio',
            'pastesite': self.site,
            'pasteid': pid,
        }
        # Timezone is UTC/Zulu
        date = datetime.strptime(raw_item['date'], '%a %b %d %H:%M:%S %Y').isoformat()
        paste_data['@timestamp'] = date
        encoded_pid = self.get_paste_id(paste_data)
        paste_data['scrape_url'] = self.raw_pattern.format(encoded_pid)
        return paste_data

    def get_paste_for_id(self, paste_id: Any) -> str:
        self.make_request(self.raw_pattern.format(paste_id))

    def get_paste_id(self, paste_obj: Dict[str, Any]) -> str:
        decoded = paste_obj.get('pasteid')
        return base62_encode(decoded)

    def get_recent_items(self, input_history: List[str]):

        history = []
        paste_list = []
        try:
            recent_page = self.make_request(self.url_recent)
            item_data = self.get_data_for_page(recent_page.text)

            for val in item_data:
                # Track paste ids to prevent dupes
                pid = val['pid']
                history.append(pid)
                if pid in input_history:
                    continue
                paste_data = self.remap_raw_item(val)
                paste_list.append(paste_data)

            return paste_list, history

        except Exception as e:
            logger.error("Unable to parse ixio items: {0}".format(e))
            return paste_list, history

    def get_data_for_page(self, page_data: str) -> List[Dict[str, Union[int, str]]]:
        page: List[Dict[str, Union[int, str]]] = []
        last_item_id = -1
        regex_matches = self._ITEM_ID_RE.findall(page_data)
        # We are going to reverse the order because ix pages are structured newest -> oldest, and this makes it simpler.
        regex_matches.reverse()
        for encoded_id, created_at in regex_matches:
            # Okay so the logic here is a bit tricky. Basically, ix's all user page only returns anonymous pastes
            # BUT! We can infer the paste ids that aren't present by filling in the blanks, because ix IDs are
            # incremental. So first, we base62 decode the value so we can use it as an int
            item_id = base62_decode(encoded_id)
            # Then, we check if we've seen another value. If this is our first, we can skip a lot of this logic.
            # (we probably don't want to go back and grab every ix paste historically for most use cases)
            if last_item_id == -1:
                page.append({'pid': item_id, 'date': created_at})
                last_item_id = item_id
            # If there has been a delta, let's traverse it.
            elif item_id - last_item_id > 1:
                # We've already hit last_item_id so we skip that and fill in the delta
                for i in range(last_item_id + 1, item_id + 1):
                    # Copy the created date as a best guess
                    page.append({'pid': i, 'date': created_at})
                last_item_id = item_id
            else:
                # If there's no delta, just add this nromally
                page.append({'pid': item_id, 'date': created_at})
                last_item_id = item_id
        return page


def recent_pastes(conf, input_history):
    site = IxDotIoSite(conf)

    # populate vars from config
    return site.get_recent_items(input_history)
