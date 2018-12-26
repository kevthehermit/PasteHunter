from telegram.ext import Updater

from common import parse_config

config = parse_config()


class TelegramOutput():
    def __init__(self):
        self.token = config['outputs']['telegram_output']['token']
        self.chat_id = config['outputs']['telegram_output']['chat_id']
        self.updater = Updater(token=self.token,
                               request_kwargs={"proxy_url": config['outputs']['telegram_output']['proxy_url']})

    def store_paste(self, paste_data):
        csv_line = '{0},{1},{2},{3},{4}'.format(paste_data['@timestamp'],
                                                paste_data['pasteid'],
                                                paste_data['YaraRule'],
                                                paste_data['scrape_url'],
                                                paste_data['pastesite'])
        self.updater.bot.send_message(chat_id=self.chat_id, text=csv_line)
