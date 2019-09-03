PostProcess
===========

There are a handful of post process modules that can run additional checks on the raw paste data. 

There are a few generic options for each input.

- **enabled**: This turns the input on and off. 
- **module**: This is used internally by pastehunter.


Email
-----
This postprocess module extracts additional information from data that includes email addresses. It will extract counts for:

- Total Emails
- Unique Email addresses
- Unique Email domains

These 3 values are then added to the meta data for storage. 

- **rule_list**: List of rules that will trigger the postprocess module. 

Base64
------

This postprocess will attempt to decode base64 data and then apply further processing on the new file data. At the moment this module only operates
when the full paste is a base64 blob, i.e. it will not extract base64 code that is embedded in other data. 

- **rule_list**: List of rules that will trigger the postprocess module. 

See the `Sandboxes documentation <sandboxes.rst>`_ for information on how to configure the sandboxes used for scanning decoded base64 data.


Entropy
-------

This postprocess module calculates shannon entropy on the raw paste data. This can be used to help identify binary and encoded or encrytped data. 

- **rule_list**: List of rules that will trigger the postprocess module. 

Compress
--------
Compresses the data using LZMA(lossless compression) if it will reduce the size. Small pastes or pastes that don't benefit from compression will not be affected by this module. 
Its outputs can be decompressed by base64-decoding, then using the `xz command <https://www.systutorials.com/docs/linux/man/1-xz/>`_.

- **rule_list**: List of rules that will trigger the postprocess module. 