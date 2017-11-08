from elasticsearch import Elasticsearch
from common import parse_config

config = parse_config()


class ElasticOutput():
    def __init__(self):
        # Set up the database connection
        es_host = config['elastic_output']['elastic_host']
        es_port = config['elastic_output']['elastic_port']
        es_user = config['elastic_output']['elastic_user']
        es_pass = config['elastic_output']['elastic_pass']
        self.es_index = config['elastic_output']['elastic_index']
        es_ssl = config['elastic_output']['elastic_ssl']
        self.test = False
        try:
            self.es = Elasticsearch(es_host, port=es_port, http_auth=(es_user, es_pass), use_ssl=es_ssl)
            self.test = True
        except Exception:
            raise Exception('Unable to Connect') from None

    def store_paste(self, paste_data):
        if self.test:
            index_name = self.es_index
            # Consider adding date to the index
            self.es.index(index=index_name, doc_type='paste', id=paste_data['key'], body=paste_data)
            print("Stored Paste {0}, Matched Rule {1}".format(paste_data['key'], paste_data['YaraRule']))
        else:
            print("Elastic Search Enabled, not configured!")