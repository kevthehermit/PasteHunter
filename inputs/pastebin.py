import requests
import logging
from datetime import datetime

logger = logging.getLogger('pastehunter')

def recent_pastes(conf, input_history):
    # populate vars from config
    paste_limit = conf['inputs']['pastebin']['paste_limit']
    api_scrape = conf['inputs']['pastebin']['api_scrape']
    history = []
    paste_list = []
    try:
        # Create the API uri
        scrape_uri = '{0}?limit={1}'.format(api_scrape, paste_limit)
        # Get some pastes and convert to json
        # Get last 'paste_limit' pastes
        paste_list_request = requests.get(scrape_uri)

        # Check to see if our IP is whitelisted or not. 
        if 'DOES NOT HAVE ACCESS' in paste_list_request.text:
            logger.error("Your IP is not whitelisted visits 'https://pastebin.com/doc_scraping_api'")
            return [], []
        paste_list_json = paste_list_request.json()

        for paste in paste_list_json:
            # Track paste ids to prevent dupes
            history.append(paste['key'])
            if paste['key'] in input_history:
                continue

            # Create a new paste dict for us to normalize
            paste_data = paste
            paste_data['pasteid'] = paste['key']
            paste_data['pastesite'] = 'pastebin.com'
            # Add a date field that kibana will map
            date = datetime.utcfromtimestamp(float(paste_data['date'])).isoformat()
            paste_data['@timestamp'] = date
            paste_list.append(paste_data)
        return paste_list, history

    except Exception as e:
        logger.error("Unable to parse paste results: {0}".format(e))
        return paste_list, history



