import requests
import logging

logger = logging.getLogger('pastehunter')

def recent_pastes(conf, input_history):
    # populate vars from config
    paste_limit = conf['inputs']['dumpz']['paste_limit']
    api_scrape = conf['inputs']['dumpz']['api_scrape']
    history = []
    paste_list = []
    try:
        # Create the API uri
        scrape_uri = '{0}?limit={1}'.format(api_scrape, paste_limit)
        # Get some pastes and convert to json
        # Get last 'paste_limit' pastes
        paste_list_request = requests.get(scrape_uri)
        paste_list_json = paste_list_request.json()

        for paste in paste_list_json['dumps']:
            # Track paste ids to prevent dupes
            history.append(paste['id'])
            if paste['id'] in input_history:
                continue

            # We don't want password protected pastes
            if paste['pwd'] == 1:
                continue

            # Create a new paste dict for us to normalize
            paste_data = paste
            paste_data['confname'] = 'dumpz'
            paste_data['pasteid'] = paste['id']
            paste_data['pastesite'] = 'dumpz.org'

            #paste_data['scrape_url'] = '{0}{1}'.format(conf['dumpz']['api_raw'], paste['id'])

            paste_data['scrape_url'] = 'https://dumpz.org/{0}/text/'.format(paste['id'])

            # Add a date field that kibana will map
            paste_data['@timestamp'] = paste_data['date']
            paste_list.append(paste_data)
        return paste_list, history

    except Exception as e:
        logger.error("Unable to parse paste results: {0}".format(e))
        return paste_list, history