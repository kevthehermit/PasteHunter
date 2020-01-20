
Migrating From a <1.2.1 Config
==================================
1.2.1 introduces some breaking configuration changes due to various project structure changes. Most notably,
all module names will need to be prefixed with "pastehunter.". So for example, this part of the configuration.::

    "gists": {
      "enabled": true,
      "module": "inputs.gists",
      "api_token": "",

Will need to change to be .::

    "gists": {
      "enabled": true,
      "module": "pastehunter.inputs.gists",
      "api_token": "",


This applies to inputs, outputs, sandboxes, and post modules. There is one more change required to migrate your configuration.
You will need to change your yara configuration to look something like this:.::

  "yara": {
    "default_rules": true,
    "custom_rules": "none",
    "exclude_rules": [],
    "blacklist": true,
    "test_rules": false
  }

If you have created any custom rules, change "none" to reflect the path to your custom rules. Finally, move your ``settings.json`` file to ``~/.config/pastehunter.json``.