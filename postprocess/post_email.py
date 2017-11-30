import re


def run(results, raw_paste_data, paste_object):
    # Use the rule name to determine what postprocess to do

    # Get total unique emails.

    all_emails = re.findall('[\w\.-]+@[\w\.-]+\.\w+', raw_paste_data)
    domain_list = []
    for email_address in all_emails:
        email_domain = email_address.split("@")
        domain_list.append(email_domain[-1])

    unique_emails = set(all_emails)
    unique_domains = set(domain_list)
    # We can filter some of the false positives from the yara match here

    if len(unique_emails) < 10:
        paste_object["results"] = []

    # Get unique domain count
    # Update the json
    paste_object["total_emails"] = len(all_emails)
    paste_object["unique_emails"] = len(unique_emails)
    paste_object["unique_domains"] = len(unique_domains)

    # Send the updated json back
    return paste_object
