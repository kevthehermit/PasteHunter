Outputs
=======

This page details all the confiuration options for the output modules/
There are a few generic options for each input.

- **enabled**: This turns the input on and off. 
- **module**: This is used internally by pastehunter.
- **classname**: This is used internally by pastehunter.

Elasticsearch
-------------
Elasticsearch was the default output. Storing all pastes and using Kibana as a graphical frontend to view the results

- **elastic_index**: The name of the index.
- **weekly_index**: Use a numbered index for each week of the year instead of a single index.
- **elastic_host**: Hostname or IP of the elasticsearch.
- **elastic_port**: Port number for elasticsearch default is 9200
- **elastic_user**: Username if using xpack / shield or basic auth.
- **elastic_pass**: Password if using xpack / shield or basic auth.
- **elastic_ssl**: True or false if Elasticsearch is served over SSL.

JSON
----

This output module will store each paste in a json file on disk. The name of the file is the pasteid. 

- **output_path**: Path on disk to store output files. 
- **store_raw**: Include the raw paste in the json file. False jsut stores metadata.
- **encode_raw**: Ignored, Reserved for future usage.

CSV
---

The CSV output will append lines to a CSV that contains basic metadata from all paste sources. The raw paste is not included.

- **output_path**: Path on disk to store output files. 

Stored elements are

- Timestamp
- Pasteid
- Yara Rules
- Scrape URL
- Pastesite

Syslog
------
Using the same format as the CSV output this writes paste metadata to a syslog server. The raw paste is not included. 

- **host**: IP or hostname of the syslog server.
- **port**: Port number of the syslog server.

SMTP
----

This output will send an email to specific email addresses depending on the YaraRules that are matched. You need to set up an SMTP server. 

- **smtp_host**: hostname for the SMTP server.
- **smtp_port**: Port number for the SMTP Server.
- **smtp_security**: One of ``tls``, ``starttls``, ``none``.
- **smtp_user**: Username for SMTP Authentication.
- **smtp_pass**: Password for SMTP Authentication.
- **recipients**: Json array of recipients and rules.
  - **address**: Email address to send alerts to.
  - **rule_list**: A list of rules to alert on. Any of the rules in this list will trigger an email.
  - **mandatory_rule_list**: List of rules that *MUST* be present to trigger an email alert. 


Slack
-----

This output will send a Notification to a slack web hook. You need to configure the URL and the channel in Slack.
Head over to https://api.slack.com/apps?new_app=1

Create a new Slack App with a Name and the workspace that you want to send alerts to. 
Once created under Add Features and Functionality select Incoming Webhooks and toggle the Active button to on.
At the bottom of the page select *Add New Webhook to Workspace* This will show another page where you select the Channel that will receive the notifications. 
Once it has authorized the app you will see a new Webhook URL. This is the URL that needs to be added to the pastehunter config. 

- **webhook_url**: Generated when creating a Slack App as described above. 
- **rule_list**: List of rules that will generate an alert. 
