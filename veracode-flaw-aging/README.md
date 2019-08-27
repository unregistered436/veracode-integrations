# Veracode "Flaw Aging" Report
This is a sample of using the Applications and Findings APIs to recreate a standard Veracode report in CSV format called the Flaw Aging Report. The flaw aging report contains the details for all applications that the user has access to, and lists all open and closed static and dynamic flaws inclusive of mitigation workflow details.
There are several fields that are not available via the APIs today, so they are designated as "<placeholder>" values for now. As they become available in the API they will be added. If you don't like that you can always replace it with "None" or another value.
  
Credit to Chris Campbell for "pythonifying" my code and for supplying the CSV formatting library. You can find him at: https://github.com/ctcampbell

## Installation
This script performs best with Python 3. It MAY work on your Python 2 setup but Python 2 will not gracefully handle unicode characters in some fields. If you have any in your data you run the chance of blowing up. Do yourself a favor and get Python 3 first. Your install method may vary for this depending on your OS so that piece isn't covered here.

This script takes advantage of Veracode HMAC authentication. Credentials must be configured first. See Veracode help at: https://help.veracode.com/reader/LMv_dtSHyb7iIxAQznC~9w/hn2qc_7fz3zFYV~e4ulRaQ for instructions

Next, the Veracode Python Authentication library needs to be installed. You will need the *custom* version that is univerally packaged
to support both Python 2 and Python 3 that can be found in the /dist directory ("security_apisigning_python-17.9.1-py2.py3-none-any.whl").
At some point Veracode will be posting a universal wheel but it isn't available just yet. See https://help.veracode.com/reader/LMv_dtSHyb7iIxAQznC~9w/imMYgCN7GTSnliwAvy3_CQ for install instructions.

Lastly, the .whl for the application is available in the /dist directory. It can be installed with the command:
```
sudo python3 -m pip install veracodeflawaging-1.6-py2.py3-none-any.whl
```
Once installed the veracodeflawaging command can be used from any directory.

Alternatively, just clone this project and run
```
python3 -m veracodeflawaging.main
```

## Usage:
-o | --output: Set the output filename. If not specified the default name flaw-aging-output.csv will be used

-a | --account: The first column is the customer account name which is not possible to determine from an API call. For reporting purposes it can be set by using this option

-c | --custom-fields: By default the values of application profile Custom 1-5 fields will be included in the report. If a different set of custom fields is desired they can be specified as a comma separated list. Be sure to include the list in quotes.

-f | --foundafter: Only return the flaws found after this date. Format YYYY-MM-DD

### Example
```
veracodeflawaging -o myflaws.csv -a "My Company" -c "Custom 1,Custom 3,Custom 5" -f 2019-01-01
