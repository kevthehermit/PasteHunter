import logging
from twilio.rest import Client
from pastehunter.common import parse_config

logger = logging.getLogger('pastehunter')
config = parse_config()

class TwilioOutput(object):
    def __init__(self):
        self.account_sid = config['outputs']['twilio_output']['account_sid']
        self.auth_token = config['outputs']['twilio_output']['auth_token']
        self.twilio_sender = config['outputs']['twilio_output']['twilio_sender']
        self.recipient_list = config['outputs']['twilio_output']['recipient_list']
        self.accepted_rules = config['outputs']['twilio_output']['rule_list']
        self.message_type = 'sms' # Whatsapp is still in beta on twilio.
        try:
            self.client = Client(self.account_sid, self.auth_token)
            self.test = True
        except Exception as e:
            logging.error("Unable to create twilio Client: {0}".format(e))
            self.test = False


    def store_paste(self, paste_data):
        if self.test:


            send = ('all' in self.accepted_rules)

            for rule in self.accepted_rules:
                if rule in paste_data['YaraRule']:
                    send = True

            if send:
                message_body = "Yara Rule {0} Found on {1}\n\r{2}".format(
                    paste_data['YaraRule'], 
                    paste_data['pastesite'], 
                    paste_data['scrape_url']
                    )

                logger.debug("Sending Twilio Message")
                if self.message_type == 'sms':
                    for recipient in self.recipient_list:
                        try:
                            message = self.client.messages.create( 
                                                        from_=self.twilio_sender,  
                                                        body=message_body,      
                                                        to=recipient 
                                                    )
                            logging.debug("Sent twilio message with ID: {0}".format(message.sid))
                        except Exception as e:
                            logging.error(e)

                elif self.message_type == 'whatsapp':
                    for recipient in self.recipient_list:
                        try:
                            message = self.client.messages.create( 
                                                        from_='whatsapp:{0}'.format(self.twilio_sender),  
                                                        body=message_body,      
                                                        to='whatsapp:{0}'.format(recipient) 
                                                    )
                            logging.debug("Sent twilio message with ID: {0}".format(message.sid))
                        except Exception as e:
                            logging.error(e)
                else:
                    logging.error("No Valid twilio message type found")
