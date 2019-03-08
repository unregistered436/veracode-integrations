# Veracode Upload and Scan Shell Script
This was originally written for CircleCI but can be used for any build system that can run a shell script in bash.

It can create a missing application profile, upload and scan, and break the build. If you do not want to create new apps then make sure to comment out or delete that section.

With the public CircleCI cloud service you cannot pre-install the Veracode Java API Wrapper, so I do a quick wget to retrieve what is the current version as of now. Unfortunately the version is hardcoded since there isn't a symbolic link URL to reference.


## Integration

Integration with CircleCI is accomplished by saving the Veracode scan script in the project's source repository. Then the Veracode scan script can be called as a step in the build job section of the project's config.yml file. See the overview of Jobs and Steps. in the CircleCI Docs to understand this further. Note that the variable $CIRCLECI_BUILD_NUM can be used as a unique scan name. See https://circleci.com/docs/2.0/env-vars/#circleci-environment-variable-descriptions for this and other variables that can be used. The Veracode API Id and Key should be created from a service account and stored as secret/protected environment variables.

Example: a new "run" command section is added as a new step in the build job section. There should be other "run" statements there to model this new one after. Note that 

```
      - run:
          name: Veracode Scan Status
          command: ./veracode-scan.sh $VERACODE_API_ID $VERACODE_API_KEY "Verademo" "/home/circleci/repo/target/Verademo.war" $CIRCLECI_BUILD_NUM
```

## The Script

veracode-scan.sh

The script syntax is:

```veracode-scan.sh <API ID> <API KEY> <Application Name> <build name with full path> <scan / build name>```

There are a few variables that can be adjusted:

* PRESCAN_SLEEP_TIME -> total wait time for prescan completion
* SCAN_SLEEP_TIME -> total wait time for scan completion
* JAVA_WRAPPER_LOCATION -> location of the Java API wrapper
* OUTPUT_FILE_LOCATION -> directory of message output files. Make sure to change the hardcoded value.
* OUTPUT_FILE_NAME -> name of file to store command output in (default is AppName-ScanName.txt)

Note that the version of the Veracode Java API used is hardcoded in the script. As new versions come out it they are published to:
https://repo1.maven.org/maven2/com/veracode/vosp/api/wrappers/vosp-api-wrappers-java/
Simply change the version number in the script directory and file name to update.

**WARNING:** Make sure the API ID and Key are set up as protected environment variables so they will not leak to the public in your .yaml file or be displayed in build output.
