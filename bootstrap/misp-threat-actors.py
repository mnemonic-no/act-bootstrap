#!/usr/bin/env python3

import argparse
import csv
from logging import error, warning

import requests
import urllib3

import act

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parseargs():
    """ Parse arguments """
    parser = argparse.ArgumentParser(
        description='Get Threat Actors (MISP Galaxy)')
    parser.add_argument(
        '--userid',
        dest='user_id',
        required=True,
        help="User ID")
    parser.add_argument(
        '--act-baseurl',
        dest='act_baseurl',
        required=True,
        help='ACT API URI')
    parser.add_argument(
        "--logfile",
        dest="log_file",
        help="Log to file (default = stdout)")
    parser.add_argument(
        "--loglevel",
        dest="log_level",
        default="info",
        help="Loglevel (default = info)")

    return parser.parse_args()


def get_misp_threat_actors():
    url = "https://raw.githubusercontent.com/MISP/misp-galaxy/master/clusters/threat-actor.json"
    r = requests.get(url, verify=False)
    return r.json()


def countrylist():
    url = "http://download.geonames.org/export/dump/countryInfo.txt"
    r = requests.get(url, verify=False)

    countries = {
        "iso": {},
        "iso3": {},
        "fips": {}
    }

    for row in csv.reader(
            [line for line in r.text.splitlines() if line[0] != '#'],
            delimiter='\t'):
        countries["iso"][row[0]] = row[4]
        countries["iso3"][row[1]] = row[4]
        countries["fips"][row[3]] = row[4]

    return countries


def add_to_act(client, ta_list):
    countries = countrylist()

    for ta in ta_list["values"]:
        name = ta["value"]

        if "meta" not in ta:
            warning("Missing meta information in MISP on Threat Actor {}".format(name))
            continue

        aliases = ta["meta"].get("synonyms", [])
        country = ta["meta"].get("country", None)

        location = None

        if country and country in countries["iso"]:
            location = countries["iso"][country]
        elif country and country in countries["iso3"]:
            location = countries["iso3"][country]
            error(
                "country code is not valid ISO code, but found match in iso3: %s\n" %
                country)
        elif country and country in countries["fips"]:
            location = countries["fips"][country]
            error(
                "country code is not valid ISO code, but found match in fips3: %s\n" %
                country)
        else:
            location = None

        if location:
            client.fact("sourceGeography")\
                .destination("location", location)\
                .source("threatActor", name)\
                .add()

        elif country:
            warning(
                "country code not found in ISO, ISO3 or FIPS: %s\n" %
                country)

        # Loop over all items under indicators in report
        for alias in aliases:
            if alias == name:
                continue  # Do not alias to ourself
            client.fact("threatActorAlias")\
                .bidirectional("threatActor", alias, "threatActor", name)\
                .add()


if __name__ == '__main__':
    args = parseargs()

    client = act.Act(
        args.act_baseurl,
        args.user_id,
        args.log_level,
        args.log_file,
        "misp-threat-actors")

    # Get all reports from SCIO
    ta = get_misp_threat_actors()

    # Add IOCs from reports to the ACT platform
    add_to_act(client, ta)
