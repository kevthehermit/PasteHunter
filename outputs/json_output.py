import base64
import lzma
import os
import datetime
import json
import logging
from common import parse_config

logger = logging.getLogger('pastehunter')

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
                logger.error("Unable to create Json Path: {0}".format(e))
                self.test = False
        else:
            self.test = True

    def store_paste(self, paste_data):
        if not config['outputs']['json_output']['store_raw']:
            del paste_data['raw_paste']
        elif config['outputs']['json_output']['compress_raw']:
            original = paste_data['raw_paste']
            orig_size = len(original.encode())
            logger.debug("Compressing paste... Pre-compression size: {}", orig_size)
            compressed = base64.b64encode(lzma.compress(paste_data['raw_paste'].encode()))
            compressed_size = len(compressed)
            logger.debug("Compressing paste... Post-compression size: {}", compressed_size)

            # In some cases compressed blobs may be larger
            # if not much data is compressed
            if orig_size > compressed_size:
                paste_data['raw_paste'] = compressed.decode('utf-8')
                logger.debug("Compressed data smaller than original blob. Keeping compressed.")
            else:
                logger.debug("Original smaller than compressed blob. Keeping original.")


        if self.test:
            json_file = os.path.join(self.json_path, str(paste_data['pasteid']))
            with open(json_file, 'w') as out:
                out.write(json.dumps(paste_data, indent=4))
        else:
            logger.error("JsonOutput Error")
