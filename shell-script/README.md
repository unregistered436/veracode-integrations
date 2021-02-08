# Veracode Upload and Scan Shell Script
This was originally written for CircleCI but can be used for any build system that can run a shell script in bash.

It can create a missing application profile, upload and scan, and break the build. If you do not want to create new apps then make sure to comment out or delete that section.

With many containerized or public build systems the developer cannot pre-install the Veracode Java API Wrapper, so the script does a quick wget to retrieve what is the current version as of now.

## Integration

The Veracode Upload & Scan script can be entered into the build system or stored as an artifact of the repository and called as a step in the build job section of the project's config.yml file. Note that the final variable is a build name or number which can be built from build server environment variables or specified manually. The Veracode API Id and Key should be created from a service account and stored as secret/protected environment variables.

Example: a new "run" command section is added as a new step in the build job section. There should be other "run" statements there to model this new one after. Note that 

```
      - run:
          name: Veracode Scan Status
          command: ./veracode-scan.sh $VERACODE_API_ID $VERACODE_API_KEY "Verademo" "/home/circleci/repo/target/Verademo.war" build_name_number
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
