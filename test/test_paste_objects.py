from inputs.pastebin import PastebinPasteSite
from inputs.slexy import SlexyPasteSite

pids_found = []


def mock_get_paste_for_pid(pid):
    pids_found.append(pid)
    return "pid_is_" + pid


class FakeRequestJson(object):
    def __init__(self, ret):
        self.ret = ret

    def json(self):
        return self.ret


def test_slexy_site():
    pid_list_fake = [0, 1, 2, 3, 4]
    slexy_site = SlexyPasteSite({})
    slexy_site.get_recent_items = lambda: pid_list_fake
    slexy_site.get_paste_for_id = lambda pid: mock_get_paste_for_pid(str(pid))
    slexy_site.remap_raw_item = lambda raw_data, pid: {"pid": 123}
    recent_pids = slexy_site.get_recent_items()
    assert recent_pids == pid_list_fake
    for pid in recent_pids:
        paste = slexy_site.get_paste_for_id(pid)
        paste_data = slexy_site.remap_raw_item(paste, pid)
        assert paste == 'pid_is_' + str(pid)
        assert paste_data == {"pid": 123}


def test_pastebin_site_remap():
    fake_conf = {
        'inputs': {
            'pastebin': {
                'paste_limit': 100,
                'api_scrape': 'https://scrape.pastebin.com/api_scraping.php'
            }
        }
    }
    data = {
        'key': 'a',
        'test': 'b',
        'date': '1582595793'
    }
    pastebin_site = PastebinPasteSite(fake_conf)
    out = pastebin_site.remap_raw_item(data)
    assert out == {'key': 'a', 'test': 'b', 'date': '1582595793', 'filename': 'a', 'confname': 'pastebin',
                   'pasteid': 'a', 'pastesite': 'pastebin.com', '@timestamp': '2020-02-25T01:56:33'}


def test_pastebin_site():
    fake_conf = {
        'inputs': {
            'pastebin': {
                'paste_limit': 100,
                'api_scrape': 'https://scrape.pastebin.com/api_scraping.php'
            }
        }
    }
    pastebin_site = PastebinPasteSite(fake_conf)
    pastebin_site.make_request = lambda url: FakeRequestJson([
        {
            'key': 'ab',
            'date': '1582595793'
        },
        {
            'key': 'bc',
            'date': '1582595793'
        }
    ])
    pastes, paste_ids = pastebin_site.get_recent_items([])
    assert paste_ids == ['ab', 'bc']
    assert pastes[0].get('key') == 'ab'
    assert pastes[1].get('key') == 'bc'
