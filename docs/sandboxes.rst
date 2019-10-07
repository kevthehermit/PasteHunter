Sandboxes
=========

There are a few sandboxes that can be configured and used in various post process steps.

There are a few generic options for each input.

- **enabled**: This turns the sandbox on and off. 
- **module**: This is used internally by pastehunter.

Cuckoo
------

If the samples match a binary file format you can optionaly send the file for analysis by a Cuckoo Sandbox.

- **api_host**: IP or hostname for a Cuckoo API endpoint. 
- **api_port**: Port number for a Cuckoo API endpoint.

Viper
-----

If the samples match a binary file format you can optionaly send the file to a Viper instance for further analysis.

- **api_host**: IP or hostname for a Viper API endpoint. 
- **api_port**: Port number for a Viper API endpoint.
