import logging
import re
from datetime import datetime
from time import sleep
from typing import Any, Dict, Optional, List, Union

from pastehunter.inputs.base_input import BasePasteSite

logger = logging.getLogger('pastehunter')


class SlexyPasteSite(BasePasteSite):

    def __init__(self, conf):
        self.url = None
        self.site = "slexy.org"
        url_slexy = "https://" + self.site
        self.url_recent = url_slexy + "/recent"
        self.url_view = url_slexy + "/view"
        self.url_raw = url_slexy + "/raw"
        self.fetch_timeout = conf.get('fetch_timeout', 15)

    def make_request(self, url: str, timeout: Optional[int] = 15, headers: Optional[Dict[str, Any]] = None):
        req = super(SlexyPasteSite, self).make_request(url, timeout, {
            'Referer': self.url_recent,
            'User-Agent': 'PasteHunter'
        })

        ratelimit_limit = int(req.headers.get('RateLimit-Limit', 30))
        remaining = int(req.headers.get('RateLimit-Remaining', 30))
        logger.debug('Remaining Slexy Ratelimit: {0}'.format(remaining))

        if req.status_code == 429:
            delay = req.headers.get('Retry-After', 60)
            sleep(delay)
            return self.make_request(url, timeout)
        # If ratelimit_limit = 60, 60/60 = 1
        # If ratelimit_limit = 30, 60/30 = 2
        sleep(30 / ratelimit_limit)
        return req.text

    def get_timestamp(self, data):
        pattern = 'Timestamp: <b>(.*?)</b>'
        ts = re.findall(pattern, data)[0]
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S %z").isoformat()

    def get_paste_id(self, paste_obj: Dict[str, Any]) -> Union[str, int]:
        return paste_obj.get('pasteid')

    def remap_raw_item(self, raw_item: [str, Dict]) -> Dict[str, Any]:
        timestamp = self.get_timestamp(raw_item)
        paste_id = self.get_paste_id(raw_item)
        raw_url = self.get_raw_link(raw_item, paste_id)
        self.get_paste_id(raw_item)
        return {
            'confname': 'slexy',
            'scrape_url': raw_url,
            'pasteid': paste_id,
            'pastesite': self.site,
            '@timestamp': timestamp
        }

    def get_raw_data(self, raw_url):
        return self.make_request(raw_url, self.fetch_timeout)

    def get_paste_for_id(self, paste_id: Any) -> str:
        return self.make_request("%s/%s" % (self.url_view, paste_id), self.fetch_timeout)

    def get_raw_link(self, data, pid):
        pattern = '<a href="/raw/%s(.*?)"' % pid
        token = re.findall(pattern, data)[0]
        return "%s/%s%s" % (self.url_raw, pid, token)

    def get_recent_items(self, input_history: List[str]):
        data = self.make_request(self.url_recent, self.fetch_timeout)
        pids = re.findall('<td><a href="/view/(.*?)">', data)
        return list(set(pids))


def recent_pastes(conf, input_history):
    history = []
    paste_list = []
    my_scraper = SlexyPasteSite(conf['inputs']['slexy'])
    recent_pids = my_scraper.get_recent_items(input_history)
    pid_to_process = set()
    for pid in recent_pids:
        if pid in input_history:
            history.append(pid)
        else:
            pid_to_process.add(pid)
    try:
        for pid in pid_to_process:
            paste_data = my_scraper.get_paste_for_id(pid)
            raw = my_scraper.get_raw_link(paste_data, pid)
            paste_data = {
                'confname': 'slexy',
                'scrape_url': raw,
                'pasteid': pid,
                'pastesite': my_scraper.site,
                '@timestamp': my_scraper.get_timestamp(paste_data)
            }
            paste_list.append(paste_data)
        return paste_list, history
    except Exception as e:
        logger.error("Unable to parse paste results: %s", e)
        return paste_list, history
