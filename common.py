import configparser

# Parse the config file in to a dict
def parse_config():
    config_dict = {}
    config = configparser.ConfigParser(allow_no_value=True)

    conf_file = 'settings.conf'

    valid = config.read(conf_file)
    if len(valid) > 0:
        config_dict['valid'] = True
        for section in config.sections():
            section_dict = {}
            for key, value in config.items(section):
                if value.lower() == 'true':
                    new_val = True
                elif value.lower() == 'false':
                    new_val = False
                else:
                    new_val = value
                section_dict[key] = new_val
            config_dict[section] = section_dict
    else:
        config_dict['valid'] = False
    return config_dict