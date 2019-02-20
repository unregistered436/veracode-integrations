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
                  "mitigation_last_rejected"]

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
        "policy_rule_passed": "<placeholder>",
        "date_last_seen": "<placeholder>",
        "owasptext": "<placeholder>",
        "issue_history_state": None,
        "date_first_seen": None,
        "date_first_not_seen": None,
        "mitigation_first_proposed": None,
        "mitigation_last_accepted": None,
        "mitigation_last_rejected": None
    }

    if parsed_finding["status"] == "OPEN":
        parsed_finding["issue_history_state"] = "New" if is_new else "Existing"
    elif parsed_finding["status"]:
        parsed_finding["issue_history_state"] = "Closed"

    found_date = datetime.strptime(finding_status_dict["found_date"], "%Y-%m-%dT%H:%M:%S.%fZ")
    parsed_finding["date_first_seen"] = "{}/{}/{} {}:{}".format(found_date.month, found_date.day, found_date.year, found_date.hour, found_date.minute)

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
    findings = get_findings(app["guid"],app["app_name"])
    app["automation_findings"] = [make_finding(app, x) for x in findings if "scan_type" in x and (x["scan_type"] == "STATIC" or x["scan_type"] == "DYNAMIC")]
    return app


def main():
    usage = "usage: %prog [options] arg1 arg2"
    parser = OptionParser(usage=usage)
    parser.add_option("-o", "--output", dest="filename", default="flaw-aging-output.csv", help="The findings output file")
    parser.add_option("-a", "--account", dest="account", default="Customer", help="Specify the customer account name for column A")
    parser.add_option("-c", "--custom-fields", dest="custom_field_lookup", help="Specify the custom fields to add to the report in a comma separated list")

    options, args = parser.parse_args()

    start_time = datetime.now()
    
    filename = options.filename
    account_name = options.account
    if options.custom_field_lookup is None:
        # change these values to your custom field names OR use the -c command line option
        custom_field_lookup = ["Custom 1", "Custom 2", "Custom 3", "Custom 4", "Custom 5"]
    else: 
        custom_field_lookup = [x.strip() for x in options.custom_field_lookup.split(",")]

    if filename == "open-finding-output.csv":
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

        app["account_name"] = account_name.encode(encoding="utf8")
        app["enterprise_name"] = None
        app["app_id"] = app["id"]
        app["app_name"] = app["profile"]["name"].encode(encoding="utf8")
        app["custom_field_values"] = custom_field_data
        app["assurance_level"] = app["profile"]["business_criticality"]
        app["business_unit"] = app["profile"]["business_unit"]["name"].encode(encoding="utf8")
        app["teams"] = "<placeholder>"
        app["tags"] = app["profile"]["tags"]
        app["origin"] = "<placeholder>"

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
