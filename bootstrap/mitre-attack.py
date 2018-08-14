#!/usr/bin/env python3

import json
import os
import sys
import argparse
from logging import error
import urllib3
import requests
import act
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MITRE_ATTACK_URL = "https://attack.mitre.org/api.php"
MITRE_PRE_ATTACK_URL = "https://attack.mitre.org/pre-attack/api.php"
MITRE_MOBILE_URL = "https://attack.mitre.org/mobile/api.php"

# https://attack.mitre.org/wiki/Special:Properties
# https://attack.mitre.org/pre-attack/index.php/Special:Properties
# https://attack.mitre.org/mobile/index.php/Special:Properties
MITRE_ALL_PROPERTIES = "Alias instance", "Allows value", "Bypasses defense", "Citation key", "Citation reference", "Citation resource", "Citation text", "Corresponds to", "Creation date", "Display precision of", "Display title of", "Display units", "Equivalent URI", "Has CAPEC ID", "Has ID", "Has URL", "Has alias", "Has alias description", "Has alias object", "Has analytic details", "Has analytic idea", "Has authors", "Has citation", "Has contributor", "Has data source", "Has day", "Has default form", "Has description", "Has detective capability", "Has display name", "Has effective permissions", "Has examples", "Has fields", "Has groups/malware", "Has improper value for", "Has link text", "Has mitigation", "Has month", "Has name", "Has network requirements", "Has platform", "Has preferred property label", "Has processing error", "Has processing error text", "Has property description", "Has query", "Has reference type", "Has remote support", "Has software", "Has software description", "Has software object", "Has software page", "Has software type", "Has subobject", "Has tactic", "Has technical description", "Has technique", "Has technique description", "Has technique name", "Has technique object", "Has title", "Has type", "Has year", "Imported from", "Is a new page", "Language code", "Modification date", "Number of page views", "Page author", "Page creator", "Provides service", "Query depth", "Query format", "Query parameters", "Query size", "Query source", "Query string", "Requires permissions", "Requires system", "Retrieved on", "Software instance", "Subcategory of", "Subproperty of", "Technique instance", "Text", "Uses software"


def parseargs():
    """ Parse arguments """
    parser = argparse.ArgumentParser(description='Insert (mitre) att&ck data into ACT')
    parser.add_argument('--userid', dest='user_id', help="User ID")
    parser.add_argument('--act-baseurl', dest='act_baseurl', help='API URI')
    parser.add_argument('--models', dest='models', default="all", help='Models (all, attack or pre-attack). Default = all"')
    parser.add_argument('--dump', dest='dump', help='Dump JSON-output to directory')
    parser.add_argument("--logfile", dest="log_file", help="Log to file (default = stdout)")
    parser.add_argument("--loglevel", dest="log_level", default="info", help="Loglevel (default = info)")

    args = parser.parse_args()

    if not (args.dump or (args.user_id and args.act_baseurl)):
        sys.stderr.write("Must specify either --dump or --userid and --act-baseurl")
        sys.exit(1)

    return args

def extract_groups_from_attack(response):
    groups = {}
    for _id, data in response.items():
        printouts = data.get("printouts", {})
        groups[_id] = {
            "title": printouts.get("Has display name")[0],
            "threatActorAlias": printouts.get("Has alias", []),
            "hasDescription": printouts.get("Has description", [])[0],
            "usesTechnique": [t["displaytitle"] for t in printouts.get("Has technique", [])],
            "usesTool": [t["fulltext"] for t in printouts.get("Uses software", [])],
            "citations": printouts.get("Citation reference", []),
            "creattion_date": int(printouts.get("Creation date")[0]["timestamp"]),
        }

    return groups

def extract_techniques_from_attack(response):
    techniques = {}
    for _id, data in response.items():
        printouts = data.get("printouts", {})
        techniques[_id] = {
            "title": printouts.get("Has display name")[0],
            "hasDataSource": printouts.get("Has data source", []),
            "usesPlatform": printouts.get("Has platform", []),
            "hasTactic": [t["fulltext"] for t in printouts.get("Has tactic", [])],
            "citations": printouts.get("Citation reference", []),
            "creattion_date": int(printouts.get("Creation date")[0]["timestamp"]),
        }

        if printouts.get("Has technical description", []):
            techniques[_id]["hasDescription"] = printouts["Has technical description"][0]

        if printouts.get("Has mitigation", []):
            techniques[_id]["mitigation"] = printouts["Has mitigation"][0]

        if printouts.get("Has analytic details", []):
            techniques[_id]["analytics"] = printouts["Has analytic details"][0]

    return techniques

def extract_tactics_from_attack(response):
    tactics = {}
    for _id, data in response.items():
        printouts = data.get("printouts", {})
        tactics[_id] = {
            "title": _id,
            "hasDescription": printouts.get("Has description", ["N/A"])[0],
            "creattion_date": int(printouts.get("Creation date")[0]["timestamp"]),
        }

    return tactics

def extract_software_from_attack(response):
    software = {}
    for _id, data in response.items():
        printouts = data.get("printouts", {})
        software[_id] = {
            "title": printouts.get("Has display name")[0],
            "toolAlias": printouts.get("Has alias", []),
            "hasDescription": printouts.get("Has description", [])[0],
            "hasSoftwareType": printouts.get("Has software type", [])[0],
            "citations": printouts.get("Citation reference", []),
            "creattion_date": int(printouts.get("Creation date")[0]["timestamp"]),
        }

    return software

def attack_fact(client, source_type, source_values, fact_type, destination_type, destination_values, link_type="linked"):
    if isinstance(destination_values, str):
        destination_values = [destination_values]

    if isinstance(source_values, str):
        source_values = [source_values]

    for source_value in source_values:
        try:
            for destination_value in destination_values:
                if source_type == destination_type and source_value == destination_value:
                    continue # Do not link to itself

                if link_type == "linked":
                    client.fact(fact_type)\
                        .source(source_type, source_value)\
                        .destination(destination_type, destination_value)\
                        .add()
                elif link_type == "bidirectional":
                    client.fact(fact_type)\
                        .bidirectional(source_type, source_value)\
                        .bidirectional(destination_type, destination_value)\
                        .add()
                else:
                    error("Illegal link_type: %s" % link_type)
        except act.base.ResponseError as e:
            error(e)
            continue

def insert_techniques(client, technique):
    for (_, data) in technique.items():
        title = data["title"]
        # description = data["hasDescription"]
        attack_fact(client, "tactic", data["hasTactic"], "usesTechnique", "technique", title)

def insert_groups(client, groups, software):
    for (_, data) in groups.items():
        title = data["title"]
        # description = data["hasDescription"]
        attack_fact(client, "threatActor", title, "threatActorAlias", "threatActor", data["threatActorAlias"], link_type="bidirectional")
        attack_fact(client, "threatActor", title, "usesTechnique", "technique", data["usesTechnique"])

        # Lookup software title from id
        tools = [software[software_id]["title"] for software_id in data["usesTool"]]

        # To lower case
        tools = [tool.lower() for tool in tools]
        attack_fact(client, "threatActor", title, "usesTool", "tool", tools)

def insert_software(client, software):
    for (_, data) in software.items():
        title = data["title"].lower()
        # description = data["hasDescription"]
        tool_alias = [alias.lower() for alias in data["toolAlias"]]
        attack_fact(client, "tool", title, "toolAlias", "tool", tool_alias, link_type="bidirectional")


def mediawiki_ask(url, q, properties = None, limit = 99999):
    filtered_result = {}

    if not properties:
        properties = []

    properties_query = "|".join(["?%s" % h for h in properties])

    if properties_query:
        properties_query = "|" + properties_query

    payload = {
        "action": "ask",
        "format": "json",
        "query": "%s%s|limit=%s" % (q, properties_query, limit)
    }

    r = requests.get(url, params = payload, verify = False).json()

    if "error" in r:
        error("url:%s, payload: %s, error: %s" % (url, payload, r["error"]))

    if "query" in r:
        # Filter out empty values
        for (key, value) in r["query"]["results"].items():
            f_val = value
            f_val["printouts"] = {p_key: p_val for (p_key, p_val) in value["printouts"].items() if p_val}
            filtered_result[key] = f_val

    return filtered_result

def out_result(filename, entries):
    with open(filename, "w") as f:
        f.write(json.dumps(
            entries,
            sort_keys=True,
            indent=4,
            separators=(',', ': ')))


if __name__ == '__main__':
    args = parseargs()

    client = act.Act(
        args.act_baseurl,
        args.user_id,
        args.log_level,
        args.log_file,
        "mitre-attack")

    if args.models in ("all", "attack", "pre-attack"):
        attack_software_raw = mediawiki_ask(MITRE_ATTACK_URL, "[[Category:Software]]", MITRE_ALL_PROPERTIES)

    if args.models == "all" or args.models == "attack":
        attack_group_raw = mediawiki_ask(MITRE_ATTACK_URL, "[[Category:Group]]", MITRE_ALL_PROPERTIES)
        attack_technique_raw = mediawiki_ask(MITRE_ATTACK_URL, "[[Category:Technique]]", MITRE_ALL_PROPERTIES)
        attack_tactic_raw = mediawiki_ask(MITRE_ATTACK_URL, "[[Category:Tactic]]", MITRE_ALL_PROPERTIES)
        attack_citation_raw = mediawiki_ask(MITRE_ATTACK_URL, "[[Citation text::+]]", MITRE_ALL_PROPERTIES)

    if args.models == "all" or args.models == "pre-attack":
        pre_attack_group_raw = mediawiki_ask(MITRE_PRE_ATTACK_URL, "[[Category:Group]]", MITRE_ALL_PROPERTIES)
        # Seems like pre-attack software (tools) does not exist
        # pre_attack_software_raw = mediawiki_ask(MITRE_PRE_ATTACK_URL, "[[Category:Software]]", MITRE_ALL_PROPERTIES)
        pre_attack_technique_raw = mediawiki_ask(MITRE_PRE_ATTACK_URL, "[[Category:Technique]]", MITRE_ALL_PROPERTIES)
        pre_attack_tactic_raw = mediawiki_ask(MITRE_PRE_ATTACK_URL, "[[Category:Tactic]]", MITRE_ALL_PROPERTIES)
        pre_attack_citation_raw = mediawiki_ask(MITRE_PRE_ATTACK_URL, "[[Citation text::+]]", MITRE_ALL_PROPERTIES)

    if args.dump:
        if not os.path.isdir(args.dump):
            os.makedirs(args.dump)

        if args.models in ("all", "attack", "pre-attack"):
            # Attack software is referenced both from attack and pre-attack
            out_result("%s/attack_software.json" % args.dump, attack_software_raw)

        if args.models in ("all", "attack"):
            out_result("%s/attack_group.json" % args.dump, attack_group_raw)
            out_result("%s/attack_technique.json" % args.dump, attack_technique_raw)
            out_result("%s/attack_tactic.json" % args.dump, attack_tactic_raw)
            out_result("%s/attack_citation.json" % args.dump, attack_citation_raw)

        if args.models in ("all", "pre-attack"):
            out_result("%s/pre-attack_group.json" % args.dump, pre_attack_group_raw)

            # Semms like pre-attack software (tools) does not exist
            # out_result("%s/pre-attack_software.json" % args.dump, pre_attack_software_raw)
            out_result("%s/pre-attack_technique.json" % args.dump, pre_attack_technique_raw)
            out_result("%s/pre-attack_tactic.json" % args.dump, pre_attack_tactic_raw)
            out_result("%s/pre-attack_citation.json" % args.dump, pre_attack_citation_raw)

    else:

        if args.models in ("all", "attack", "pre-attack"):
            attack_software = extract_software_from_attack(attack_software_raw)

        if args.models in ("all", "attack"):
            attack_tactic = extract_tactics_from_attack(attack_tactic_raw)
            attack_technique = extract_techniques_from_attack(attack_technique_raw)
            attack_group = extract_groups_from_attack(attack_group_raw)

            insert_techniques(client, attack_technique)
            insert_software(client, attack_software)
            insert_groups(client, attack_group, attack_software)

        if args.models in ("all", "pre-attack"):
            pre_attack_tactic = extract_tactics_from_attack(pre_attack_tactic_raw)
            pre_attack_technique = extract_techniques_from_attack(pre_attack_technique_raw)
            pre_attack_group = extract_groups_from_attack(pre_attack_group_raw)

            insert_techniques(client, pre_attack_technique)

            # Note: Links to attack_software (not preattack)
            insert_groups(client, pre_attack_group, attack_software)

        # https://attack.mitre.org/wiki/Using_the_API
