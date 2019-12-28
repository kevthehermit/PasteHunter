import logging
import os
import datetime
from pastehunter.common import parse_config

logger = logging.getLogger('pastehunter')
config = parse_config()


class CSVOutput(object):
    def __init__(self):
        base_path = config['outputs']['csv_output']['output_path']
        # Get todays CSV
        dtg = datetime.date.today().strftime("%Y-%m-%d")
        csv_name = 'pastes_{0}.csv'.format(dtg)
        self.csv_path = os.path.join(base_path, csv_name)

        if not os.path.exists(base_path):
            try:
                os.makedirs(base_path)
                self.test = True
            except OSError as e:
                logger.error("Unable to create CSV Path: {}".format(e))
                self.test = False
        else:
            self.test = True

    def store_paste(self, paste_data):
        if self.test:
            # date, _id, YaraRule, raw_url
            csv_line = '{0},{1},{2},{3},{4}'.format(paste_data['@timestamp'],
                                                paste_data['pasteid'],
                                                paste_data['YaraRule'],
                                                paste_data['scrape_url'],
                                                paste_data['pastesite'])
            with open(self.csv_path, 'a') as out:
                out.write('{0}\n'.format(csv_line))
        else:
            logging.error("CSV Output Error. Output path '{}' was never created.".format(self.csv_path))
