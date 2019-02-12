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


import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC


base_uri = "https://api.veracode.com/appsec/v1/applications"


def get_apps():
    all_apps = []
    apps_base_uri = base_uri + "?page={}"

    page = 0
    more_pages = True
    print("Retrieving applications list")

    while more_pages:
        uri = apps_base_uri.format(page)
        response = requests.get(uri, auth=RequestsAuthPluginVeracodeHMAC())
        if not response.ok:
            print("Error retrieving application data. HTTP status code: {}".format(response.status_code))
            if response.status_code == 401:
                print("Check that your Veracode API account credentials are correct.")
            raise requests.exceptions.RequestException()

        page_data = response.json()
        total_pages = page_data.get('page', {}).get('total_pages', 0)
        apps_page = page_data.get('_embedded', {}).get('applications', [])
        all_apps += apps_page  
        
        page += 1
        more_pages = page < total_pages - 1

    return all_apps


def get_findings(guid,app):
    # For now, findings do not show compliance against the policy. Need a new API link to view results against policy
    all_findings = []
    base_findings_uri = base_uri + "/{}/findings?page={}"
    
    page = 0
    more_pages = True
    print("Retrieving findings for application: {}".format(app))

    while more_pages:
        uri = base_findings_uri.format(guid, page)
        response = requests.get(uri, auth=RequestsAuthPluginVeracodeHMAC())
        if not response.ok:
            print("Error retrieving findings for application GUID {}. HTTP status code: {}".format(guid, response.status_code))
            if response.status_code == 401:
                    print("Check that your Veracode API account credentials are correct.")
            raise requests.exceptions.RequestException()

        page_data = response.json()
        total_pages = page_data.get('page', {}).get('total_pages', 0)
        findings_page = page_data.get('_embedded', {}).get('findings', [])
        all_findings += findings_page

        page += 1
        more_pages = page < total_pages - 1

    return all_findings
