import lzma
import base64
import logging
from pastehunter.common import parse_config
logger = logging.getLogger('pastehunter')
config = parse_config()

def run(results, raw_paste_data, paste_object):
    if config['outputs']['json_output']['store_raw']:
        original = raw_paste_data
        orig_size = len(original.encode())
        logger.debug("Compressing paste... Pre-compression size: {}", orig_size)
        compressed = base64.b64encode(lzma.compress(raw_paste_data.encode()))
        compressed_size = len(compressed)
        logger.debug("Compressing paste... Post-compression size: {}", compressed_size)

        # In some cases compressed blobs may be larger
        # if not much data is compressed
        if orig_size > compressed_size:
            paste_object['raw_paste'] = compressed.decode('utf-8')
            logger.debug("Compressed data smaller than original blob. Keeping compressed.")
        else:
            logger.debug("Original smaller than compressed blob. Keeping original.")

    # Regardless of modification, return the paste object
    return paste_object
