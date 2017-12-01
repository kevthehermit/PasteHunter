import io
import re
import hashlib
import gzip
import logging
import requests
from base64 import b64decode
# This gets the raw paste and the paste_data json object
from common import parse_config
conf = parse_config()



def run(results, raw_paste_data, paste_object):
    # Figure out which b64 rule fire

    b64_re = '(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)'
    b64_strings = re.findall(b64_re, raw_paste_data)

    # Set a counter for multiple streams.
    counter = 0
    for b64_str in b64_strings:
        for rule in results:
            if rule == 'b64_gzip':
                # Lets try to decode and get a file listing.
                # Also get the MD5 of the decoded file
                try:
                    uncompressed = gzip.decompress(b64decode(b64_str))
                    try:
                        encoded_paste_data = uncompressed.encode('utf-8')
                        paste_object["decompressed_stream"] = encoded_paste_data
                    except:
                        logging.error("Unable to store data")
                except Exception as e:
                    logging.error("Unable to decompress gzip stream")
            if rule == 'b64_exe':
                try:
                    raw_exe = b64decode(b64_str)
                    paste_object["exe_size"] = len(raw_exe)
                    paste_object["exe_md5"] = hashlib.md5(raw_exe).hexdigest()
                    paste_object["exe_sha256"] = hashlib.sha256(raw_exe).hexdigest()
                    paste_object["VT"] = 'https://www.virustotal.com/#/file/{0}'.format(paste_object["exe_md5"])

                    # Cuckoo
                    if conf["post_process"]["post_b64"]["cuckoo"]["enabled"]:
                        try:
                            task_id = send_to_cuckoo(raw_exe, paste_object["pasteid"])
                            paste_object["Cuckoo Task ID"] = task_id
                            logging.info("exe submitted to Cuckoo with task id {0}".format(task_id))
                        except Exception as e:
                            logging.error("Unabled to submit sample to cuckoo")

                    # Viper
                    if conf["post_process"]["post_b64"]["viper"]["enabled"]:
                        send_to_cuckoo(raw_exe, paste_object["pasteid"])

                except Exception as e:
                    logging.error("Unable to decode exe file")

        # Increase the counter
        counter += 1

    # Get unique domain count
    # Update the json

    # Send the updated json back
    return paste_object


def send_to_cuckoo(raw_exe, pasteid):
    cuckoo_ip = conf["post_process"]["post_b64"]["cuckoo"]["api_host"]
    cuckoo_port = conf["post_process"]["post_b64"]["cuckoo"]["api_port"]
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
            logging.error(submit_file)

    return task_id

