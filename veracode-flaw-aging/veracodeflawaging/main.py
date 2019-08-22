# MIT License
#
# Copyright (c) 2019 Veracode
# Author: Patrick McNeil & Chris Campbell
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# *** PURPOSE
# Create a flaw aging report for static and dynamic findings

# *** SETUP
# Default API credentials are used for whichever user is running this script.
# Setup instructions can be found in the "Enabling HMAC Authentication"
# section at help.veracode.com.

import subprocess
import sys
from optparse import OptionParser
from datetime import datetime, timedelta
from multiprocessing import Pool

from veracodeflawaging.api import get_apps, get_findings
from veracodeflawaging.unicodecsv import create_csv


app_values = ["account_name", "enterprise_name", "app_id", "app_name", "assurance_level", "business_unit",
              "origin", "teams", "tags"]

finding_values = ["flaw_id", "flaw_name", "policy_rule_passed", "cwe_id", "category", "severity", "exploitability",
                  "status", "issue_history_state", "mitigation_status", "analysis_type", "owasptext", "date_first_seen",
                  "date_last_seen", "date_first_not_seen", "mitigation_first_proposed", "mitigation_last_accepted",
                  "mitigation_last_rejected", "recommendation", "module_name", "location"]

severity_lookup = ["Informational", "Very Low", "Low", "Medium", "High", "Very High"]
exploit_lookup = ["Very Unlikely", "Unlikely", "Neutral", "Likely", "Very Likely"]
mitigation_dict = {
    "NONE": "Not Mitigated",
    "PROPOSED": "Mitigation Proposed",
    "APPROVED": "Mitigation Approved",
    "REJECTED": "Mitigation Rejected",
    "AUTOMATED": "Not Mitigated"
}
proposal_lookup = ["FP", "APPDESIGN", "OSENV", "NETENV", "NOACTIONTAKEN", "CUSTOMCLEANSERPROPOSED", "REMEDIATED", "BYENV", "BYDESIGN", "ACCEPTRISK"]


def make_finding(app, finding):
    
    finding_status_dict = list(finding["finding_status"].values())[0]
    is_new = finding_status_dict["new_in_context"]

    parsed_finding = {
        "status": finding_status_dict["status"],
        "flaw_id": finding["issue_id"],
        "flaw_name": finding["cwe"]["name"],
        "cwe_id": finding["cwe"]["id"],
        "category": finding["finding_category"]["name"],
        "severity": severity_lookup[finding["severity"]],    
        "exploitability": exploit_lookup[finding["exploitability"] + 2],
        "mitigation_status": mitigation_dict[finding_status_dict["resolution_status"]],
        "analysis_type": finding["scan_type"],
        "policy_rule_passed": None,
        "date_last_seen": None,
        "owasptext": None,
        "issue_history_state": None,
        "date_first_seen": None,
        "date_first_not_seen": None,
        "mitigation_first_proposed": None,
        "mitigation_last_accepted": None,
        "mitigation_last_rejected": None,
    }

    # Recommendation, module name, and location are not in the default flaw aging report. If you do not want these then
    # remove this code block and remove the headings from the "finding_values" global variable.
    if parsed_finding["analysis_type"] == "SCA":
        parsed_finding["recommendation"] = finding["cwe"]["recommendation"]
        parsed_finding["module_name"] = finding_status_dict["finding_source"]["component_filename"]
        parsed_finding["location"] = finding_status_dict["component_path"]
    elif parsed_finding["analysis_type"] == "STATIC":
        parsed_finding["recommendation"] = finding["cwe"]["recommendation"]
        if "procedure" in str(finding_status_dict["finding_source"]) and "relative_location" in str(finding_status_dict["finding_source"]):
            parsed_finding["module_name"] = finding_status_dict["finding_source"]["module"]
            parsed_finding["location"] = "{}:{}".format(finding_status_dict["finding_source"]["procedure"], finding_status_dict["finding_source"]["relative_location"])
        else:
            parsed_finding["module_name"] = finding_status_dict["finding_source"]["module"]
            parsed_finding["location"] = "{}:{}".format(finding_status_dict["finding_source"]["file_path"],finding_status_dict["finding_source"]["file_line_number"])
    elif parsed_finding["analysis_type"] == "DYNAMIC":
        parsed_finding["recommendation"] = finding["cwe"]["recommendation"]
        parsed_finding["module_name"] = "Dynamic Analysis"
        parsed_finding["location"] = finding_status_dict["finding_source"]["url"]  
    elif parsed_finding["analysis_type"] == "MANUAL":
        parsed_finding["recommendation"] = finding_status_dict["finding_source"]["remediation_desc"]
        parsed_finding["module_name"] = "Manual Pentest"
        parsed_finding["location"] = finding_status_dict["finding_source"]["module"]
    # End of non-default section

    if finding["violates_policy"]:
        parsed_finding["policy_rule_passed"] = "0"
    else:
        parsed_finding["policy_rule_passed"] = "1"

    if parsed_finding["status"] == "OPEN":
        parsed_finding["issue_history_state"] = "New" if is_new else "Existing"
    elif parsed_finding["status"]:
        parsed_finding["issue_history_state"] = "Closed"

    found_date = datetime.strptime(finding_status_dict["found_date"], "%Y-%m-%dT%H:%M:%S.%fZ")
    parsed_finding["date_first_seen"] = "{}/{}/{} {}:{}".format(found_date.month, found_date.day, found_date.year, found_date.hour, found_date.minute)

    if finding_status_dict["last_seen_date"]:
        date_last_seen = datetime.strptime(finding_status_dict["last_seen_date"], "%Y-%m-%dT%H:%M:%S.%fZ")
        parsed_finding["date_last_seen"] = "{}/{}/{} {}:{}".format(date_last_seen.month, date_last_seen.day, date_last_seen.year, found_date.hour, found_date.minute)

    if finding_status_dict["resolved_date"]:
        resolved_date = datetime.strptime(finding_status_dict["resolved_date"], "%Y-%m-%dT%H:%M:%S.%fZ")
        parsed_finding["date_first_not_seen"] = "{}/{}/{} {}:{}".format(resolved_date.month, resolved_date.day, resolved_date.year, resolved_date.hour, resolved_date.minute)

    for annotation in finding["annotations"]:
        if not parsed_finding["mitigation_last_accepted"] and annotation["action"] == "APPROVED":
            adate = datetime.strptime(annotation["created"], "%Y-%m-%dT%H:%M:%S.%fZ")
            parsed_finding["mitigation_last_accepted"] = "{}/{}/{} {}:{}".format(adate.month, adate.day, adate.year, adate.hour, adate.minute)
        if not parsed_finding["mitigation_last_rejected"] and annotation["action"] == "REJECTED":
            rdate = datetime.strptime(annotation["created"], "%Y-%m-%dT%H:%M:%S.%fZ")
            parsed_finding["mitigation_last_rejected"] = "{}/{}/{} {}:{}".format(rdate.month, rdate.day, rdate.year, rdate.hour, rdate.minute)
        if annotation["action"] in proposal_lookup:
            pdate = datetime.strptime(annotation["created"],"%Y-%m-%dT%H:%M:%S.%fZ")
            parsed_finding["mitigation_first_proposed"] = "{}/{}/{} {}:{}".format(pdate.month, pdate.day, pdate.year, pdate.hour, pdate.minute)                
   
    return [app[value] for value in app_values] + app["custom_field_values"] + [parsed_finding[value] for value in finding_values]


def app_findings(app):
    findings = get_findings(app["guid"],app["app_name"],app["found_after"],app["modified_after"])
    app["automation_findings"] = [make_finding(app, x) for x in findings if "scan_type" in x and (x["scan_type"] == "STATIC" or x["scan_type"] == "DYNAMIC")]
    return app

def validate(date_text):
    try:
        datetime.strptime(date_text, '%Y-%m-%d')
    except ValueError:
        raise ValueError("Incorrect date format. Dates should be YYYY-MM-DD")

def main():
    usage = "usage: %prog [options] arg1 arg2"
    parser = OptionParser(usage=usage,version='Version 1.6')
    parser.add_option("-o", "--output", dest="filename", default="flaw-aging-output.csv", help="The findings output file")
    parser.add_option("-a", "--account", dest="account", default="Customer", help="Specify the customer account name for column A")
    parser.add_option("-c", "--custom-fields", dest="custom_field_lookup", help="Specify the custom fields to add to the report in a comma separated list")
    parser.add_option("-f", "--foundafter", dest="found_after", help="Filter results to those found for the first time after the provided date. Format: YYYY-MM-DD")
    parser.add_option("-m", "--modifiedafter", dest="modified_after", help="Filter results to those modified after the provided date. Format: YYYY-MM-DD")

    options, args = parser.parse_args()

    start_time = datetime.now()
    
    filename = options.filename
    account_name = options.account
    found_after = options.found_after
    if found_after: validate(found_after)

    modified_after = options.modified_after
    if modified_after: validate(modified_after)

    if modified_after and found_after:
        print("Found after and modified after options cannot be specified together.")
        exit(0)

    if options.custom_field_lookup is None:
        # change these values to your custom field names OR use the -c command line option
        custom_field_lookup = ["Custom 1", "Custom 2", "Custom 3", "Custom 4", "Custom 5"]
    else: 
        custom_field_lookup = [x.strip() for x in options.custom_field_lookup.split(",")]

    if filename == "flaw-aging-output.csv":
        print("Using default file name (can change with -o option).")

    apps = get_apps()

    for app in apps:
        custom_fields = app["profile"].get("custom_fields")
        custom_field_values = [x["value"] for x in custom_fields] if custom_fields else []
        custom_field_names = [x["name"] for x in custom_fields] if custom_fields else []
        custom_field_data = []

        for x, field_name in enumerate(custom_field_lookup, start=0):
            if custom_fields and field_name in custom_field_names:
                custom_field_data.append(custom_field_values[custom_field_names.index(field_name)])
            else: custom_field_data.append("")

        app["account_name"] = account_name
        app["enterprise_name"] = None
        app["app_id"] = app["id"]
        app["app_name"] = app["profile"]["name"]
        app["custom_field_values"] = custom_field_data
        app["assurance_level"] = app["profile"]["business_criticality"]
        app["business_unit"] = app["profile"]["business_unit"]["name"]

# Teams coming later
        app["teams"] = None
        app["tags"] = app["profile"]["tags"]
        app["origin"] = None
        app["found_after"] = found_after
        app["modified_after"] = modified_after

    if apps:
        pool = Pool(processes=10)
        apps_with_findings = pool.map(app_findings, apps)
        all_findings = [finding for app in apps_with_findings for finding in app["automation_findings"]]

        all_findings.sort(key=lambda x: (x[2], x[len(app_values) + len(custom_field_names)]))

        csv_header = app_values + custom_field_lookup + finding_values
        create_csv([csv_header] + all_findings, filename)

    print("Total elapsed time (HH:MM:SS.us): {}".format(datetime.now() - start_time))
    print("Done.")


if __name__ == "__main__":
    main()
