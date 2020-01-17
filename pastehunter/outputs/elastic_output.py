from elasticsearch import Elasticsearch
from pastehunter.common import parse_config
from datetime import datetime
import logging

logger = logging.getLogger('pastehunter')
config = parse_config()


class ElasticOutput():
    def __init__(self):
        # Set up the database connection
        es_host = config['outputs']['elastic_output']['elastic_host']
        es_port = config['outputs']['elastic_output']['elastic_port']
        es_user = config['outputs']['elastic_output']['elastic_user']
        es_pass = config['outputs']['elastic_output']['elastic_pass']
        self.es_index = config['outputs']['elastic_output']['elastic_index']
        self.weekly = config['outputs']['elastic_output']['weekly_index']
        es_ssl = config['outputs']['elastic_output']['elastic_ssl']
        self.test = False
        try:
            self.es = Elasticsearch(es_host, port=es_port, http_auth=(es_user, es_pass), use_ssl=es_ssl)
            self.test = True
        except Exception as e:
            logger.error(e)
            raise Exception('Unable to Connect') from None

    def store_paste(self, paste_data):
        if self.test:
            index_name = self.es_index
            if self.weekly:
                year_number = datetime.date(datetime.now()).isocalendar()[0]
                week_number = datetime.date(datetime.now()).isocalendar()[1]
                index_name = '{0}-{1}-{2}'.format(index_name, year_number, week_number)
            # ToDo: With multiple paste sites a pasteid collision is more likly!
            try:
                pasteid = str(paste_data['pasteid'])
                self.es.index(index=index_name, doc_type='paste', id=pasteid, body=paste_data)
                logger.debug("Stored {0} Paste {1}, Matched Rule {2}".format(paste_data['pastesite'],
                                                                             paste_data['pasteid'],
                                                                             paste_data['YaraRule']
                                                                             )
                             )
            except Exception as e:
                logger.error(e)
        else:
            logger.error("Elastic Search Enabled, not configured!")
