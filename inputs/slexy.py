import logging
import re
import urllib.request as urllib
from datetime import datetime

logger = logging.getLogger('pastehunter')


class SlexySite(object):

    def __init__(self):
        self.site = "slexy.org"
        url_slexy = "http://" + self.site
        self.url_recent = url_slexy + "/recent"
        self.url_view = url_slexy + "/view"
        self.url_raw = url_slexy + "/raw"

    def view_link(self, pid):
        return "%s/%s" % (self.url_view, pid)

    def raw_link(self, pid, args):
        return "%s/%s%s" % (self.url_raw, pid, args)


class SlexyPaste(SlexySite):
    def __init__(self, pid):
        super(SlexyPaste, self).__init__()
        self.pid = pid
        self.site = self.site
        self.url = None
        self.timestamp = None
        self.parse()

    def parse(self):
        data = urllib.urlopen(self.view_link(self.pid)).read().decode('utf-8')
        self.url = self.get_raw_link(data)
        self.timestamp = self.get_timestamp(data)

    def get_raw_link(self, data):
        pattern = '<a href="/raw/%s(.*?)"' % self.pid
        token = re.findall(pattern, data)[0]
        return self.raw_link(self.pid, token)

    def get_raw_data(self):
        return urllib.urlopen(self.url).read().decode('utf-8')

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
        getdata = urllib.urlopen(self.url_recent).read().decode('utf-8')
        pids = re.findall('<td><a href="/view/(.*?)">', getdata)
        recents = []
        for pid in pids:
            recents.append(SlexyPaste(pid))
        return recents


def recent_pastes(conf, input_history):
    history = []
    paste_list = []
    try:
        my_scraper = SlexyScraper()
        for paste in my_scraper.get_recents():
            history.append(paste.pid)
            if paste.pid in input_history:
                continue
            paste_data = {}
            paste_data['scrape_url'] = paste.url
            paste_data['pasteid'] = paste.pid
            paste_data['pastesite'] = paste.site
            paste_data['@timestamp'] = paste.timestamp
            paste_list.append(paste_data)
        return paste_list, history
    except Exception as e:
        logger.error("Unable to parse paste results: %s", e)
        return paste_list, history
