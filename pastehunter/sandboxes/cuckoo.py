import io
import logging
import requests
from pastehunter.common import parse_config
conf = parse_config()

logger = logging.getLogger('pastehunter')

def upload_file(raw_file, paste_object):
    try:
        task_id = send_to_cuckoo(raw_file, paste_object["pasteid"])
        paste_object["Cuckoo Task ID"] = task_id
        logger.info("exe submitted to Cuckoo with task id {0}".format(task_id))
    except Exception as e:
        logger.error("Unabled to submit sample to cuckoo")

    # Send any updated json back
    return paste_object

def send_to_cuckoo(raw_exe, pasteid):
    cuckoo_ip = conf["sandboxes"]["cuckoo"]["api_host"]
    cuckoo_port = conf["sandboxes"]["cuckoo"]["api_port"]
    cuckoo_host = 'http://{0}:{1}'.format(cuckoo_ip, cuckoo_port)
    submit_file_url = '{0}/tasks/create/file'.format(cuckoo_host)
    files = {'file': ('{0}.exe'.format(pasteid), io.BytesIO(raw_exe))}
    submit_file = requests.post(submit_file_url, files=files).json()
    task_id = None
    try:
        task_id = submit_file['task_id']
    except KeyError:
        try:
            task_id = submit_file['task_ids'][0]
        except KeyError:
            logger.error(submit_file)

    return task_id
