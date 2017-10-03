from elasticsearch import Elasticsearch
from common import parse_config

config = parse_config()


class ElasticOutput():
    def __init__(self):
        # Set up the database connection
        es_host = config['elastic_output']['elastic_host']
        es_port = config['elastic_output']['elastic_port']
        self.test = False
        try:
            self.es = Elasticsearch(es_host, port=es_port)
            self.test = True
        except Exception:
            raise Exception('Unable to Connect') from None

    def store_paste(self, paste_data):
        if self.test:
            self.es.index(index='paste-test', doc_type='paste', id=paste_data['key'], body=paste_data)
            print("Stored Paste {0}".format(paste_data['key']))
        else:
            print("Elastic Search Enabled, not configured!")