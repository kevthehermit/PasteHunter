import logging
import math
import re
from datetime import datetime

import fnmatch
import requests

# Future work/improvement that can happen here: support PR diffs, they contain a patch URL
# Set some logging options
logger = logging.getLogger('pastehunter')
logging.getLogger('requests').setLevel(logging.ERROR)

api_uri = 'https://api.github.com/events'
# This event refers to a commit being pushed, and is
# probably the most significant thing we're concerned about.
event_types = ['PushEvent']
api_version = 'application/vnd.github.v3+json'  # Set Accept header to force api v3
# Important note from github:
# 'We delay the public events feed by five minutes, which means the most recent event returned by the public events API actually occurred at least five minutes ago.'

# Beware, git diffs can sometimes be very large files, including binaries and zips.
#                MB    KB     B
diff_size_limit = 500 * 1000 * 1000

blob_hash_pattern = re.compile('https://github.com/.*/blob/(.*?)/.*')


def _make_request(url, headers):
    req = requests.get(url, headers=headers)
    reset_date = datetime.utcfromtimestamp(float(req.headers['X-RateLimit-Reset'])).isoformat()
    logger.info('Remaining Limit: {0}. Resets at {1}'.format(req.headers['X-RateLimit-Remaining'],
                                                              reset_date))

    if req.status_code == 200:
        return req.json()

    if req.status_code == 401:
        logger.error('Auth Failed')
        return None

    elif req.status_code == 403:
        logger.error('Login Attempts Exceeded')
        return None

def get_blob_hash(file_dict):
    blob_url = file_dict.get('blob_url')
    return blob_hash_pattern.findall(blob_url)[0]

def recent_pastes(conf, input_history):
    oauth_token = conf['inputs']['github']['api_token']
    conf_limit = conf['inputs']['github']['api_limit']
    gh_limit = min(conf_limit, 300)
    # From GitHub Docs (https://developer.github.com/v3/activity/events/#list-public-events):
    # Events support pagination, however the per_page option is unsupported. The fixed page size is 30 items. Fetching up to ten pages is supported, for a total of 300 events.
    # We modify this to be 100 per page, but the limit is still 300.
    if gh_limit != conf_limit:
        logger.warning('gh_limit exceeds github items returned from public feed. Limiting to 300.')
    headers = {'user-agent': 'PasteHunter',
               'Accept': api_version,
               'Authorization': 'token {0}'.format(oauth_token)}

    # calculate number of pages
    page_count = int(math.ceil(gh_limit / 100))

    result_pages = []
    history = []
    paste_list = []

    gh_file_blacklist = conf['inputs']['github']['file_blacklist']
    gh_user_blacklist = conf['inputs']['github']['user_blacklist']
    ignore_bots = conf['inputs']['github']['ignore_bots']

    try:
        # Get the required amount of entries via pagination
        for page_num in range(1, page_count + 1):
            url = '{0}?page={1}&per_page=100'.format(api_uri, page_num)
            logger.debug('Fetching page: {0}'.format(page_num))
            req = _make_request(url, headers)
            if req is not None:
                result_pages.append(req)

        # Parse results

        for page in result_pages:
            for event_meta in page:
                # Track paste ids to prevent dupes
                event_id = event_meta['id']
                history.append(event_id)
                if event_id in input_history:
                    continue
                if event_meta['type'] not in event_types:
                    logger.debug('Skipping event {} due to unwanted type "{}"'.format(event_id, event_meta['type']))
                # Actor may have been deleted or changed
                if 'actor' in event_meta:
                    # If the username is None, this will return false, while event_meta['login'] would error.
                    if event_meta.get('actor').get('login') in gh_user_blacklist:
                        logger.info('Blacklisting GitHub event from user: {0}'.format(event_meta.get('login')))
                        continue
                    login = event_meta.get('actor').get('login')
                    if ignore_bots and login and login.endswith("[bot]"):
                        logger.info('Ignoring GitHub event from bot user: {}'.format(login))
                        continue

                payload = event_meta.get('payload')
                if not 'commits' in payload:
                    # Debug, because this is high output
                    logger.debug('Skipping event {} due to no commits.'.format(event_id))
                    continue
                for commit_meta in payload.get('commits'):
                    commit_url = commit_meta.get('url')
                    commit_data = _make_request(commit_url, headers)
                    if not commit_data:
                        logger.info('No data returned for url {}. Skipping...'.format(commit_url))
                        continue
                    if commit_data.get('committer') and commit_data.get('committer').get('login') in gh_user_blacklist:
                        logger.info('Blacklisting GitHub event from user: {0}'.format(event_meta['owner']['login']))
                        continue
                    for file_obj in commit_data.get('files'):
                        is_blacklisted = False
                        file_path = file_obj.get('filename')
                        for pattern in gh_file_blacklist:
                            if fnmatch.fnmatch(file_path, pattern):
                                logger.info('Blacklisting file {0} from event {1} (matched pattern "{2}")'.format(file_path, event_id, pattern))
                                is_blacklisted = True
                                break

                        if is_blacklisted:
                            continue

                        github_data = file_obj
                        github_data['confname'] = 'github'
                        github_data['@timestamp'] = event_meta['created_at']
                        github_data['pasteid'] = get_blob_hash(file_obj) or event_id
                        github_data['user'] = event_meta.get('actor').get('login')
                        github_data['pastesite'] = 'github.com'
                        github_data['scrape_url'] = file_obj.get('raw_url')
                        # remove some original keys just to keep it a bit cleaner
                        del github_data['raw_url']
                        paste_list.append(github_data)

        # Return results and history
        return paste_list, history
    except Exception as e:
        logger.exception('Unable to parse paste results: {0}'.format(e), e)
        return paste_list, history
