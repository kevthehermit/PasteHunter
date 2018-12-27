from telegram.ext import Updater

from common import parse_config
import logging

logger = logging.getLogger('pastehunter')
config = parse_config()


class TelegramOutput():
    def __init__(self):
        self.token = config['outputs']['telegram_output']['token']
        self.chat_id = config['outputs']['telegram_output']['chat_id']
        self.updater = Updater(token=self.token,
                               request_kwargs={"proxy_url": config['outputs']['telegram_output']['proxy_url']})

    def store_paste(self, paste_data):
        if paste_data['pastesite']=='pastebin.com':
            url = paste_data['full_url']
        else:
            url = paste_data['scrape_url']
        send_data = "From {0}: Matched Rule: {1}, See : {2}".format(paste_data['pastesite'], str(paste_data['YaraRule']), url)

        self.updater.bot.send_message(chat_id=self.chat_id, text=send_data)
        logger.debug("send a message %s"%send_data)
