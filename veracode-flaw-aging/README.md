# Veracode "Flaw Aging" Report
This is a sample of using the Applications and Findings APIs to recreate a standard Veracode report in CSV format called the Flaw Aging Report. The flaw aging report contains the details for all applications that the user has access to, and lists all open and closed static and dynamic flaws inclusive of mitigation workflow details.
There are several fields that are not available via the APIs today, so they are designated as "<placeholder>" values for now. As they become available in the API they will be added.

## Installation
This script takes advantage of Veracode HMAC authentication. Credentials must be configured first. See Veracode help at: https://help.veracode.com/reader/LMv_dtSHyb7iIxAQznC~9w/hn2qc_7fz3zFYV~e4ulRaQ for instructions

Next, the Veracode Python Authentication library needs to be installed. See https://help.veracode.com/reader/LMv_dtSHyb7iIxAQznC~9w/imMYgCN7GTSnliwAvy3_CQ for instructions.

Lastly, a .whl is available in the /dist directory. This can be installed with the command:
```
sudo python pip install veracodeflawaging-1.1-py2.py3-none-any.whl
```
Once installed the veracodeflawaging command can be used from any directory.

Alternatively, just clone this project and run
```python -m veracodeflawaging.main```

## Usage:
-o | --output: Set the output filename. If not specified the default name flaw-aging-output.csv will be used

-a | --account: The first column is the customer account name which is not possible to determine from an API call. For reporting purposes it can be set by using this option

-c | --custom fields: By default the values of application profile Custom 1-5 fields will be included in the report. If a different set of custom fields is desired they can be specified as a comma separated list. Be sure to include the list in quotes.

### Example
```
veracodeflawaging -o myflaws.csv -a "Veracode" -c "Custom 1,Custom 3, Custom 5"
