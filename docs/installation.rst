Installation
============

There are a few ways to install PasteHunter. Pip is the recommended route for stable releases.


Pip Installation
------------------
**Note** Pip or setup.py installation will require ``gcc`` and ``wheel``.

Pip installation is supported for versions after 1.2.1. This can easily be done using:

``pip install pastehunter``

You will then need to configure pastehunter. To do this, use:.::

    mkdir -p ~/.config
    wget https://raw.githubusercontent.com/kevthehermit/PasteHunter/master/settings.json.sample -O ~/.config/pastehunter.json

Then modify ~/.config/pastehunter.json to match your desired settings and run the project using ``pasthunter-cli``

Local Installation
------------------

Pastehunter
^^^^^^^^^^^
If you want to run the latest stable version grab the latest release from https://github.com/kevthehermit/PasteHunter/releases.
If you want to run the development version clone the repository or download the latest archive. 

Pastehunter has very few dependancies you can install all the python libraries using the requirements.txt file and ``sudo pip3 install -r requirements.txt``


Yara
^^^^
Yara is the scanning engine that scans each paste. Use the official documentation to install yara and the python3 library. 
https://yara.readthedocs.io/en/latest/gettingstarted.html#compiling-and-installing-yara

All yara rules are stored in the YaraRules directory. An index.yar file is created at run time that includes all additional yar files in this directory. 
To add or remove yara rules, simply add or remove the rule file from this directory. 



Elastic Search
^^^^^^^^^^^^^^
If you want to use the elastic search output module you will need to install elastic search. Pastehunter has been tested with version 6.x of Elasticsearch.
To install follow the offical directions on https://www.elastic.co/guide/en/elasticsearch/reference/current/deb.html.

You will also need the elasticsearch python library which can be installed using ``sudo pip3 install elasticsearch``.

Kibana
^^^^^^
Kibana is the frontend search to Elasticsearch. If you have enabled the Elasticsearch module you probably want this. 
To install follow the offical directions on https://www.elastic.co/guide/en/kibana/current/deb.html.



Docker Installation
-------------------
You will find a Dockerfile that will build the latest stable version of PasteHunter. 


This can be used with the included docker-compose.yml file. 
A sample podspec for kubernets is coming soon. 


Configuration
-------------
**See** :doc:`this page <./migrating>` **for help migrating configs from older versions (<1.2.1)**

Before you can get up and running you will need to set up the basic config. 
Copy the settings.json.sample to settings.json and edit with your editor of choice. 

Yara
^^^^

- **rule_path**: defaults to the YaraRules directory in the PasteHunter root.
- **blacklist**: If set to true, any pastes that match this rule will be ignored.
- **test_rules**: Occasionaly I release some early test rules. Set this to ``true`` to use them.

log
^^^

Logging for the application is configured here. 

- **log_to_file**: true or false, default is stdout.
- **log_file**: filename to log out to.
- **logging_level**: numerical value for logging level see the table below.
- **log_path**: path on disk to write log_file to.
- **format**: python logging format string - https://docs.python.org/3/library/logging.html#formatter-objects

======== =========
Level    Numerical
======== =========
CRITICAL 50
ERROR    40
WARNING  30
INFO     20
DEBUG    10
NETSET   0
======== =========

general
^^^^^^^

General config options here.

- **run_frequency**: Sleep delay between fetching list of inputs to download. This helps rate limits. 


For Input, Output and Postprocess settings please refer to the relevant sections of the docs. 
    

Starting
--------

You can run pastehunter by calling the script by name. 

``python3 pastehunter-cli``

Service
^^^^^^^

You can install pastehunter as a service if your planning on running for long periods of time. An example systemd service file is show below

Create a new service file ``/etc/systemd/system/pastehunter.service``

Add the following text updating as appropriate for your setup paying attention to file paths and usernames.:: 


    [Unit]
    Description=PasteHunter
    
    [Service]
    WorkingDirectory=/opt/PasteHunter
    ExecStart=/usr/bin/python3 /opt/PasteHunter/pastehunter-cli
    User=localuser
    Group=localuser
    Restart=always
    
    [Install]
    WantedBy=multi-user.target


Before starting the service ensure you have tested the pastehunter app on the command line and identify any errors. Once your ready then update systemctl ``systemctl daemon-reload`` enable the new service ``systemctl enable pastehunter.service`` and start the service ``systemctl start pastehunter`` 
