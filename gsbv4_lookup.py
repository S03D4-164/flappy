#!/usr/bin/env python

import os, sys
import requests, json
from configparser import ConfigParser

def mkthreatinfo(urls=[]):
    threat_types = [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "THREAT_TYPE_UNSPECIFIED",
    ]
    platform_types = [
        "ALL_PLATFORMS",
        #"WINDOWS",
    ]
    threat_entry_types = ["URL"]

    threat_entries = []
    for url in urls:
        u = {"url":url}
        threat_entries.append(u)

    threat_info = {
      "threatTypes": threat_types,
      "platformTypes": platform_types,
      "threatEntryTypes": threat_entry_types,
      "threatEntries": threat_entries,
    }

    return threat_info


def main():
    key = ""
    config = sys.argv[1]
    if os.path.isfile(config):
        cp = ConfigParser()
        cp.read(config)
        if 'api' in cp:
            key = cp['api']['key']
    if not key:
        sys.exit("API key not found.")
    api = "https://safebrowsing.googleapis.com/v4/"
    api += "threatMatches:find"
    api += "?key=" + key
    
    url = sys.argv[2]
    urls = []
    if os.path.isfile(url):
        with open(url, "r") as fh:
            for u in fh:
                urls.append(u.strip())
    else:
        urls.append(sys.argv[2])

    headers = {'content-type': 'application/json'}

    body = {}
    client = {
            "clientId": "gsbla4",
            "clientVersion": "0.0.1"
    }
    #body["client"] = client

    body["threatInfo"] = mkthreatinfo(urls)
    print(body)
    r = requests.post(api, data=json.dumps(body), headers=headers)
    print(r.text)

if __name__ == '__main__':
    main()
