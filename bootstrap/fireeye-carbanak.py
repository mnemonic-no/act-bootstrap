#!/usr/bin/env python3

""" FireEye Carbanak facts """

import argparse
import io
import ipaddress
import re

import pyexcel_xlsx
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import act
from act.fact import fact_chain
from act.helpers import handle_fact

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def is_ip(addr):
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        pass
    return False


def parseargs():
    """ Parse arguments """
    parser = argparse.ArgumentParser(description='FireEye Carbanak Facts')
    parser.add_argument('--userid', dest='user_id', help="User ID")
    parser.add_argument('--act-baseurl', dest='act_baseurl', help='ACT API URI')
    parser.add_argument('--md5-lookup', required=True, help='ACT API URI')
    parser.add_argument("--logfile", dest="log_file", help="Log to file (default = stdout)")
    parser.add_argument("--loglevel", default="info", help="Loglevel (default = info)")
    return parser.parse_args()


def get_xlsx_report(url, sheet_name):
    """ Download and parse excel report """
    r = requests.get(url, verify=False)
    data = pyexcel_xlsx.get_data(io.BytesIO(r.content))
    return data[sheet_name]


def get_md5_lookup(filename):
    """
    Read file with md5,sha256
    """
    lookup = {}

    with open(filename) as f:
        for row in f:
            (md5, sha256) = row.strip().split(",")
            lookup[md5] = sha256

    return lookup


def carbanak_report(client, md5_lookup):
    """
    Download and parse carbanak report
    Add facts for md5, sha256, c2 and campaigns
    """
    for row in get_xlsx_report(
            "https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/carbanak-report.xlsx",
            "Sheet1")[1:]:  # First row is header

        md5 = row[0]
        campaign = row[3]
        c2_list = row[4:]
        sha256 = md5_lookup.get(md5)

        if not md5:
            continue

        if sha256:
            content = sha256
        else:
            content = "*"  # Unknown

        chain = []

        if content != "*":
            handle_fact(client.fact("represents")
                        .source("hash", md5)
                        .destination("content", content))

        if campaign and not campaign == "NA" and isinstance(campaign, str):
            chain = []

            # Create chain
            # (hash)? -represents> (content) -observedIn> (incident) -attributedTo-> (campaign)

            if content == "*":  # start at md5, since content is unknown
                chain.append(client.fact("represents")
                             .source("hash", md5)
                             .destination("content", "*"))

            # continue with content, which can either be "*" or sha256
            chain.append(client.fact("observedIn", "incident")
                         # content sha256 if we have that, otherwise "*"
                         .source("content", content)
                         .destination("incident", "*"))

            chain.append(client.fact("attributedTo")
                         .source("incident", "*")
                         .destination("campaign", campaign))

            for fact in fact_chain(*chain):  # Find content value (placeholder)
                handle_fact(fact)

                # Replace content with placeholder object
                if content == "*" and fact.destination_object.type.name == "content":
                    content = fact.destination_object.value

        for c2 in c2_list:
            c2_no_port = re.sub(r':.*$', "", c2)
            port = re.sub(r'^.*:', "", c2)

            chain = []

            # Create chain
            # (hash)? -represents> (content) -connectsTo> (uri) <-componentOf- (uri|fqdn)

            if content == "*":  # Start at md5
                chain.append(client.fact("represents")
                             .source("hash", md5)
                             .destination("content", "*"))

            # continue with content, which can either be "*" or sha256
            chain.append(client.fact("connectsTo")
                         .source("content", content)
                         .destination("uri", "*"))

            object_type = "ipv4" if is_ip(c2_no_port) else "fqdn"

            # Add componentOf (either ipv4 or fqdn)
            chain.append(client.fact("componentOf")
                         .source(object_type, c2_no_port)
                         .destination("uri", "*"))

            for fact in fact_chain(*chain):  # Find content value (placeholder)
                handle_fact(fact)

                # Replace content with placeholder object if this was previously unknown
                if content == "*" and fact.destination_object.type.name == "content":
                    content = fact.destination_object.value

                # Add port to uri placeholder
                if port and fact.destination_object.type.name == "uri":
                    handle_fact(client.fact("port", str(port))
                                .source("uri", fact.destination_object.value))

        if content != "*":
            handle_fact(client.fact("classifiedAs")
                        .source("content", content)
                        .destination("tool", "carbanak"))


if __name__ == '__main__':
    args = parseargs()

    carbanak_report(
        act.Act(
            args.act_baseurl,
            args.user_id,
            args.loglevel,
            args.log_file,
            "fireye-carbanak"),
        get_md5_lookup(args.md5_lookup),
    )
