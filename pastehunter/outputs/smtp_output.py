import smtplib
import email.encoders
import email.header
import email.mime.base
import email.mime.multipart
import email.mime.text
from email.utils import formatdate
from email.mime.multipart import MIMEMultipart
import json
import logging

from pastehunter.common import parse_config
logger = logging.getLogger('pastehunter')

config = parse_config()

class SMTPOutput():
    def __init__(self):
        smtp_object = config['outputs']['smtp_output']
        self.smtp_host = smtp_object['smtp_host']
        self.smtp_port = smtp_object['smtp_port']
        self.smtp_security = smtp_object['smtp_security']
        self.smtp_user = smtp_object['smtp_user']
        self.smtp_pass = smtp_object['smtp_pass']
        if 'recipients' in smtp_object:
            self.recipients = smtp_object['recipients']
        else:
            # maintain compatibility with older single recipient config format
            self.recipients = {'main': {'address': smtp_object['recipient'],
                                        'rule_list': smtp_object['rule_list'],
                                        'mandatory_rule_list': []}}


    def _send_mail(self, send_to_address, paste_data):
        logger.info("crafting email for {0}".format(send_to_address))

        # Create the message
        msg = MIMEMultipart()
        msg['Subject'] = 'PasteHunter Alert {0}'.format(', '.join(paste_data['YaraRule']))
        msg['From'] = self.smtp_user
        msg['To'] = send_to_address
        msg["Date"] = formatdate(localtime=True)

        # Attach the body
        body = 'Rules : {0}\n' \
               'Paste : {1} from {2}\n\n' \
               'A Copy of the paste has been attached'.format(', '.join(paste_data['YaraRule']),
                                                              paste_data['pasteid'],
                                                              paste_data['pastesite'])
        msg.attach(email.mime.text.MIMEText(body, 'plain'))

        # Attach the raw paste as JSON
        attachment = email.mime.base.MIMEBase('application', 'json')
        json_body = json.dumps(paste_data)
        attachment.set_payload(json_body)
        email.encoders.encode_base64(attachment)
        attachment.add_header('Content-Disposition', 'attachment; filename="Alert-{0}.json"'.format(paste_data['pasteid']))
        msg.attach(attachment)

        # Connect to the SMTP server and send
        if self.smtp_security == 'ssl':
            smtp_conn = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port)
        else:
            smtp_conn = smtplib.SMTP(self.smtp_host, self.smtp_port)
        smtp_conn.ehlo()
        if self.smtp_security == 'tls':
            smtp_conn.starttls()
        smtp_conn.login(self.smtp_user, self.smtp_pass)
        smtp_conn.send_message(msg)
        smtp_conn.quit()

        logger.info("Sent mail to {0} with rules {1}".format(send_to_address,
                                                              ', '.join(paste_data['YaraRule'])))


    def _check_recipient_rules(self, paste_data, recipient_name):

            # Read each recipient's config
            recipient = self.recipients[recipient_name]
            recipient_address = recipient['address']
            all_rules_mandatory = False
            if len(recipient['mandatory_rule_list']):
                recipient_rule_list = recipient['mandatory_rule_list']
                all_rules_mandatory = True
            else:
                recipient_rule_list = recipient['rule_list']

            # Check if the recipient has special rule 'all' meaning it gets all alerts
            if 'all' in recipient_rule_list:
                self._send_mail(recipient_address, paste_data)
                return

            # Check if all of the recipient's rules need to be found in the alert
            if all_rules_mandatory:
                if all(elem in paste_data['YaraRule'] for elem in recipient_rule_list):
                    self._send_mail(recipient_address, paste_data)
                return

            # Nominal case, check if at least one rule is found in the alert
            if any(elem in paste_data['YaraRule'] for elem in recipient_rule_list):
                self._send_mail(recipient_address, paste_data)
                return


    def store_paste(self, paste_data):
        for recipient_name in self.recipients:
            self._check_recipient_rules(paste_data, recipient_name)
