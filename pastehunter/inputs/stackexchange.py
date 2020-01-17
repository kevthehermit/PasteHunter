import requests
import math
import logging
from datetime import datetime

# Set some logging options
logger = logging.getLogger('pastehunter')
logging.getLogger('requests').setLevel(logging.ERROR)

# Test API Key from the docs - U4DMV*8nvpm3EOpvf69Rxw((
# https://api.stackexchange.com/2.2/questions?key=U4DMV*8nvpm3EOpvf69Rxw((&site=stackoverflow&page=1&pagesize=100&order=desc&sort=creation&filter=default



def recent_pastes(conf, input_history):
    api_key = conf['inputs']['stackexchange']['api_key']
    api_scrape = conf['inputs']['stackexchange']['api_scrape']
    site_list = conf['inputs']['stackexchange']['site_list']
    store_filter = conf['inputs']['stackexchange']['store_filter']
    question_body_filter = '!bA1dOlliDM)pi9'
    pagesize = 100 # Default = 30
    headers = {'user-agent': 'PasteHunter'}

    if api_key == '':
        logger.error("No API Key configured for StackExchange Access")
        return [], []

    result_pages = []
    history = []
    paste_list = []

    try:
        
        # For each of the stack sites we want to query
        for site in site_list:
            logger.info("Query Stack Exchange site: {0}".format(site))

            # Create the API uri
            scrape_uri = '{0}?key={1}&site={2}&page=1&pagesize=100&order=desc&sort=creation&filter={3}'.format(api_scrape, api_key, site, store_filter)
            # Get some pastes and convert to json
            # Get last 'paste_limit' pastes
            paste_list_request = requests.get(scrape_uri)
    
            # ToDo: Add an API rate test in here. 
            paste_list_json = paste_list_request.json()
            
            if "error_id" in paste_list_json:
                logging.error("StackExchange API Error: {0}".format(paste_list_json['error_message']))
                return [], []
            
            
    
            for question in paste_list_json['items']:
                # Track question ids to prevent dupes
                history.append(question['question_id'])
                if question['question_id'] in input_history:
                    continue
    
                # Create a new question dict for us to normalize
                question_data = question
                question_data['filename'] = ''
                question_data['confname'] = "stackexchange"
                # Force type to string else it breaks ES Index mappings
                question_data['pasteid'] = str(question['question_id']) 
                question_data['pastesite'] = site
                # Set the raw uri to avoid breaking other things. Defaults to empty if not found
                question_data['scrape_url'] = question.get('link', '')
                # Get the author and then trim the data we store. 
                question_data['username'] = question['owner']['display_name']
                del question_data['owner']
                # Add a date field that kibana will map
                date = datetime.utcfromtimestamp(float(question_data['creation_date'])).isoformat()
                question_data['@timestamp'] = date
                paste_list.append(question_data)
            
            
            # Record API Quota on last call to save some logging. 
            quota_max = paste_list_json['quota_max']
            quota_remaining = paste_list_json['quota_remaining']
        
        logger.info("Used {0} of {1} of StackExchange api quota".format(quota_remaining, quota_max))
        # Return the pastes and update history
        return paste_list, history

    except Exception as e:
        logger.error("Unable to parse question results: {0}".format(e))
        return paste_list, history