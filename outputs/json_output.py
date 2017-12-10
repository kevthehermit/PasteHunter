import os
import datetime
import json
from common import parse_config

config = parse_config()

class JsonOutput():
    def __init__(self):
        base_path = config['outputs']['json_output']['output_path']
        self.json_path = base_path
        if not os.path.exists(base_path):
            try:
                os.makedirs(base_path)
                self.test = True
            except OSError as e:
                print("Unable to create Json Path: {0}".format(e))
                self.test = False
        else:
            self.test = True

    def store_paste(self, paste_data):
        if not config['outputs']['json_output']['store_raw']:
            del paste_data['raw_paste']

        if self.test:
            json_file = os.path.join(self.json_path, str(paste_data['pasteid']))
            with open(json_file, 'w') as out:
                out.write(json.dumps(paste_data, indent=4))
        else:
            print("JsonOutput Error")
