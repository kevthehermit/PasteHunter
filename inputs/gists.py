import requests
import math
import logging
from datetime import datetime

# Set some logging options
logger = logging.getLogger('pastehunter')
logging.getLogger('requests').setLevel(logging.ERROR)

api_uri = 'https://api.github.com/gists/public'
api_version = 'application/vnd.github.v3+json'  # Set Accept header to force api v3

# Some people use gists to store large blobs of data every 17 minutes. This just slows down the kibana UI



def recent_pastes(conf, input_history):
    oauth_token = conf['inputs']['gists']['api_token']
    gist_limit = conf['inputs']['gists']['api_limit']
    headers = {'user-agent': 'PasteHunter',
               'Accept': api_version,
               'Authorization': 'token {0}'.format(oauth_token)}

    # calculate number of pages
    page_count = int(math.ceil(gist_limit / 100))

    result_pages = []
    history = []
    paste_list = []

    gist_file_blacklist = conf['inputs']['gists']['file_blacklist']
    gist_user_blacklist = conf['inputs']['gists']['user_blacklist']

    try:
        # Get the required amount of entries via pagination
        for page_num in range(1, page_count + 1):
            url = '{0}?page={1}&per_page=100'.format(api_uri, page_num)
            logger.debug("Fetching page: {0}".format(page_num))
            req = requests.get(url, headers=headers)
            # Check some headers
            reset_date = datetime.utcfromtimestamp(float(req.headers['X-RateLimit-Reset'])).isoformat()
            # logging.info("Limit Reset: {0}".format(reset_date))
            logger.info("Remaining Limit: {0}. Resets at {1}".format(req.headers['X-RateLimit-Remaining'],
                                                                      reset_date))

            if req.status_code == 200:
                result_pages.append(req.json())

            if req.status_code == 401:
                logger.error("Auth Failed")

            elif req.status_code == 403:
                logger.error("Login Attempts Exceeded")

        # Parse results

        for page in result_pages:
            for gist_meta in page:
                # Track paste ids to prevent dupes
                history.append(gist_meta['id'])
                if gist_meta['id'] in input_history:
                    continue

                if gist_meta['user'] in gist_user_blacklist:
                    logger.info("Blacklisting Gist from user: {0}".format(gist_meta['owner']['login']))
                    continue

                for file_name, file_meta in gist_meta['files'].items():

                    if file_name in gist_file_blacklist:
                        logger.info("Blacklisting Paste {0}".format(file_name))
                        continue

                    gist_data = file_meta
                    gist_data['confname'] = 'gists'
                    gist_data['@timestamp'] = gist_meta['created_at']
                    gist_data['pasteid'] = gist_meta['id']
                    gist_data['user'] = gist_meta['user']
                    gist_data['pastesite'] = 'gist.github.com'
                    gist_data['scrape_url'] = file_meta['raw_url']
                    # remove some origional keys just to keep it a bit cleaner
                    del gist_data['raw_url']
                    paste_list.append(gist_data)

        # Return results and history
        return paste_list, history
    except Exception as e:
        logger.error("Unable to parse paste results: {0}".format(e))
        return paste_list, history
