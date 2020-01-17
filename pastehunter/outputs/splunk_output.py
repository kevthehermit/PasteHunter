from pastehunter.common import parse_config
import json
import logging
import splunklib.client as client

logger = logging.getLogger('pastehunter')
config = parse_config()

class SplunkOutput():
    def __init__(self):
        # Set up the database connection
        splunk_host = config['outputs']['splunk_output']['splunk_host']
        splunk_port = config['outputs']['splunk_output']['splunk_port']
        splunk_user = config['outputs']['splunk_output']['splunk_user']
        splunk_pass = config['outputs']['splunk_output']['splunk_pass']
        self.splunk_index = config['outputs']['splunk_output']['splunk_index']

        try:
            self.service = client.connect(
                host=splunk_host,
                port=splunk_port,
                username=splunk_user,
                password=splunk_pass,
                autologin=True)

            self.index = self.service.indexes[self.splunk_index]
        except Exception as e:
            logger.error(e)
            raise Exception('Unable to connect or missing index') from None

    def store_paste(self, paste_data):
        # Make a copy so we don't affect any other output modules
        local_data = dict(paste_data)
        if not config['outputs']['splunk_output']['store_raw']:
            del local_data['raw_paste']

        try:
            # The edit_tcp capability is required to access this API
            sourcetype = config['outputs']['splunk_output']['splunk_sourcetype']
            self.index.submit(json.dumps(local_data), sourcetype=sourcetype)
        except Exception as e:
            logger.exception('Error submitting paste_data to splunk', e)
