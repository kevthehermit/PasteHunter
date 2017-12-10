import smtplib
import email.encoders
import email.header
import email.mime.base
import email.mime.multipart
import email.mime.text
from email.mime.multipart import MIMEMultipart
import json
import logging

from common import parse_config

config = parse_config()

class SMTPOutput():
    def __init__(self):
        self.smtp_host = config['outputs']['smtp_output']['smtp_host']
        self.smtp_port = config['outputs']['smtp_output']['smtp_port']
        self.smtp_tls = config['outputs']['smtp_output']['smtp_tls']
        self.smtp_user = config['outputs']['smtp_output']['smtp_user']
        self.smtp_pass = config['outputs']['smtp_output']['smtp_pass']
        self.recipient = config['outputs']['smtp_output']['recipient']
        self.alert_list = config['outputs']['smtp_output']['rule_list']

    def store_paste(self, paste_data):

        alert_email = False
        # Alert on All
        if 'all' in self.alert_list:
            alert_email = True

        # Alert on specific rules e.g. custom_keywords
        if 'all' not in self.alert_list:
            for yara in paste_data['YaraRule']:
                if yara in self.alert_list:
                    alert_email = True

        # To Alert or not to Alert
        if not alert_email:
            return

        msg = MIMEMultipart()
        msg['Subject'] = 'PasteHunter Alert {0}'.format(paste_data['YaraRule'])
        msg['From'] = self.smtp_user
        msg['To'] = self.recipient

        body = 'This is the body of the email'
        json_body = json.dumps(paste_data)
        # Attach the body
        msg.attach(email.mime.text.MIMEText(body, 'plain'))

        # Attach the raw paste

        json_att = email.mime.base.MIMEBase('application', 'json')
        json_att.set_payload(json_body)
        email.encoders.encode_base64(json_att)
        json_att.add_header('Content-Disposition', 'attachment; filename="Alert.json"')
        msg.attach(json_att)

        # Connect and send

        smtp_conn = smtplib.SMTP(self.smtp_host, self.smtp_port)

        smtp_conn.ehlo()
        if self.smtp_tls:
            smtp_conn.starttls()

        smtp_conn.login(self.smtp_user, self.smtp_pass)
        logging.info("Email Sent")
        smtp_conn.send_message(msg)
        smtp_conn.quit()
