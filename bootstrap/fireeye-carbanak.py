#!/usr/bin/env python3

import io
import re
import argparse
import pyexcel_xlsx
import requests
# import arrow
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import act
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def is_ip(addr):
    return re.search(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', addr)

def parseargs():
    """ Parse arguments """
    parser = argparse.ArgumentParser(description='PDNS enrichment')
    parser.add_argument('--userid', dest='user_id', required=True, help="User ID")
    parser.add_argument('--act-baseurl', dest='act_baseurl', required=True, help='ACT API URI')
    parser.add_argument("--logfile", dest="log_file", help="Log to file (default = stdout)")
    parser.add_argument("--loglevel", dest="log_level", default="info", help="Loglevel (default = info)")

    return parser.parse_args()

def get_xlsx_report(url, sheet_name):
    r = requests.get(url, verify=False)
    data = pyexcel_xlsx.get_data(io.BytesIO(r.content))
    return data[sheet_name]

def carbanak_report(client):
    for row in get_xlsx_report(
            "https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/carbanak-report.xlsx",
            "Sheet1")[1:]: # First row is header

        md5 = row[0]
        # compile_time = arrow.get(row[1])
        # protocol_version = row[2]
        campaign = row[3]
        c2_list = row[4:]

        if not md5:
            continue

        client.fact("isTool")\
                .source("hash", md5)\
                .destination("tool", "carbanak")\
                .add()

        if campaign and not campaign == "NA" and isinstance(campaign, str):

            client.fact("seenIn", "campaign")\
                    .source("hash", md5)\
                    .destination("campaign", campaign)\
                    .add()

        for c2 in c2_list:
            c2_no_port = re.sub(r':.*$', "", c2)

            if is_ip(c2_no_port):
                fact_value = "ipv4"
                object_type = "ipv4"
            else:
                fact_value = "fqdn"
                object_type = "fqdn"

            client.fact("usesC2", fact_value)\
                    .source("hash", md5)\
                    .destination(object_type, c2_no_port)\
                    .add()

if __name__ == '__main__':
    args = parseargs()
    client = act.Act(
        args.act_baseurl,
        args.user_id,
        args.log_level,
        args.log_file,
        "fireye-carbanak")

    carbanak_report(client)
