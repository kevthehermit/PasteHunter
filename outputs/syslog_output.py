import socket
from common import parse_config

config = parse_config()

class SyslogOutput():

    def store_paste(self, paste_data):
        host = config['syslog_output']['host']
        port = int(config['syslog_output']['port'])

        syslog_line = '{0} "{1}" "{2}" "{3}"'.format(paste_data['@timestamp'],
                                            paste_data['key'],
                                            paste_data['YaraRule'],
                                            paste_data['scrape_url'])
        syslog = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        syslog.connect((host, port))
        syslog.send(syslog_line.encode('utf-8'))
        syslog.close()
