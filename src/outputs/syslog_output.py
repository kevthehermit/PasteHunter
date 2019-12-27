import socket
from common import parse_config

config = parse_config()

class SyslogOutput():

    def store_paste(self, paste_data):
        host = config['outputs']['syslog_output']['host']
        port = config['outputs']['syslog_output']['port']

        syslog_line = '"{0}" "{1}" "{2}" "{3}" "{4}"'.format(paste_data['@timestamp'],
                                                paste_data['pasteid'],
                                                paste_data['YaraRule'],
                                                paste_data['scrape_url'],
                                                paste_data['pastesite'])
        syslog = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        syslog.connect((host, port))
        syslog.send(syslog_line.encode('utf-8'))
        syslog.close()
