from pastehunter.postprocess.post_email import run as run_email


def test_email_filter_post():
    email_dummy = """
    garbage text sdgusdfjhuhjgnujidhj
    jim@gmail.com:abc123
    sally@yahoo.com:cba321
    jim@gmail.com:abc123
    sally@yahoo.com:cba321
    jim@gmail.com:abc123
    sally@yahoo.com:cba321
    jim@gmail.com:abc123
    sally@yahoo.com:cba321
    jim@gmail.com:abc123
    sally@yahoo.com:cba321
    garbage text sdgusdfjhuhjgnujidhj
    """
    results = run_email(None, email_dummy, {})
    assert results["total_emails"] == 10
    assert results['unique_emails'] == 2
    assert results['unique_domains'] == 2