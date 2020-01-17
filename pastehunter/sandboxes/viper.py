import io
import logging
import requests
from pastehunter.common import parse_config
conf = parse_config()

logger = logging.getLogger('pastehunter')

def upload_file(raw_file, paste_object):
    viper_ip = conf["sandboxes"]["viper"]["api_host"]
    viper_port = conf["sandboxes"]["viper"]["api_port"]
    viper_host = 'http://{0}:{1}'.format(viper_ip, viper_port)

    submit_file_url = '{0}/tasks/create/file'.format(viper_host)
    files = {'file': ('{0}.exe'.format(paste_object["pasteid"]), io.BytesIO(raw_file))}
    submit_file = requests.post(submit_file_url, files=files).json()

    # Send any updated json back
    return paste_object
