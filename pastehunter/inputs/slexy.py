import logging
import re
from datetime import datetime
from time import sleep

import requests

logger = logging.getLogger('pastehunter')


class SlexySite(object):

    def __init__(self):
        self.site = "slexy.org"
        url_slexy = "https://" + self.site
        self.url_recent = url_slexy + "/recent"
        self.url_view = url_slexy + "/view"
        self.url_raw = url_slexy + "/raw"
        self.url = None

    def request_view_link(self, pid):
        return self._make_request("%s/%s" % (self.url_view, pid))

    def raw_link(self, pid, args):
        return "%s/%s%s" % (self.url_raw, pid, args)

    def _make_request(self, url):
        req = requests.get(url, headers={
            'Referer': self.url_recent,
            'User-Agent': 'PasteHunter'
        }, timeout=10)
        ratelimit_limit = int(req.headers.get('RateLimit-Limit', 30))
        remaining = int(req.headers.get('RateLimit-Remaining', 30))
        logger.debug('Remaining Slexy Ratelimit: {0}'.format(remaining))

        if req.status_code == 429:
            timeout = req.headers.get('Retry-After', 60)
            sleep(timeout)
            return self._make_request(url)
        # If ratelimit_limit = 60, 60/60 = 1
        # If ratelimit_limit = 30, 60/30 = 2
        sleep(30 / ratelimit_limit)
        return req.text


class SlexyPaste(SlexySite):
    def __init__(self, pid):
        super(SlexyPaste, self).__init__()
        self.pid = pid
        self.site = self.site
        self.timestamp = None
        self.parse()

    def parse(self):
        data = self.request_view_link(self.pid)
        self.timestamp = self.get_timestamp(data)
        self.url = self.get_raw_link(data)

    def get_raw_link(self, data):
        pattern = '<a href="/raw/%s(.*?)"' % self.pid
        token = re.findall(pattern, data)[0]
        return self.raw_link(self.pid, token)

    def get_raw_data(self):
        return self._make_request(self.url_raw)

    def get_timestamp(self, data):
        pattern = 'Timestamp: <b>(.*?)</b>'
        ts = re.findall(pattern, data)[0]
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S %z").isoformat()

    def __repr__(self):
        return self.pid


class SlexyScraper(SlexySite):

    def __init__(self):
        super(SlexyScraper, self).__init__()

    def get_recents(self):
        getdata = self._make_request(self.url_recent)
        pids = re.findall('<td><a href="/view/(.*?)">', getdata)
        return list(set(pids))


def recent_pastes(conf, input_history):
    history = []
    paste_list = []
    my_scraper = SlexyScraper()
    recent_pids = my_scraper.get_recents()
    pid_to_process = set()
    for pid in recent_pids:
        if pid in input_history:
            history.append(pid)
        else:
            pid_to_process.add(pid)
    try:
        for pid in pid_to_process:
            paste = SlexyPaste(pid)
            history.append(paste.pid)
            paste_data = {
                'confname': 'slexy',
                'scrape_url': paste.url,
                'pasteid': paste.pid,
                'pastesite': paste.site,
                '@timestamp': paste.timestamp
            }
            paste_list.append(paste_data)
        return paste_list, history
    except Exception as e:
        logger.error("Unable to parse paste results: %s", e)
        return paste_list, history
