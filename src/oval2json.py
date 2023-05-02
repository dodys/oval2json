from lxml import etree as ET
import argparse
import json
import sys
import threading

XMLNS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
XMLNSOVAL = ""


# definitions are either 'patch' or 'vulnerability' depending on the vendor
# or data type
def parse_oval_definitions(root, ns, data):
    definitions = root.findall('.//*[@class="patch"]', namespaces=ns)
    if not definitions:
        definitions = root.findall('.//*[@class="vulnerability"]', namespaces=ns)
    for definition in definitions:
        defi = {}
        defi["id"] = definition.get("id")
        defi["title"] = definition.findtext(".//xmlns:title", namespaces=ns)
        defi["severity"] = definition.findtext(".//xmlns:severity", namespaces=ns)
        defi["tests"] = []
        defi["cves"] = []
        for cve in definition.findall(".//xmlns:cve", namespaces=ns):
            defi["cves"].append({"cve_id": cve.text,
                                 "public_date": cve.get("public"),
                                 "severity": cve.get("severity"),
                                 "cvss_score": cve.get("cvss_score"),
                                 "cvss_vector": cve.get("cvss_vector")
                                 })
        for criterion in definition.findall(".//xmlns:criteria/xmlns:criterion", namespaces=ns):
            test = {}
            test["id"] = criterion.get("test_ref")
            test["comment"] = criterion.get("comment")
            defi["tests"].append(test)
        data.append(defi)


def parse_oval_tests(root, ns, tests):
    tsts = root.find(".//xmlns:tests", namespaces=ns)
    for child in tsts.getchildren():
        tst = {}
        tst["id"] = child.get("id")
        for item in child.getchildren():
            if item.get("object_ref"):
                tst["object_ref"] = item.get("object_ref")
            elif item.get("state_ref"):
                tst["state_ref"] = item.get("state_ref")
        tests.append(tst)


def parse_oval_objects(root, ns, objects):
    objs = root.find(".//xmlns:objects", namespaces=ns)
    for child in objs.getchildren():
        obj = {}
        obj["object_ref"] = child.get("id")
        for item in child.getchildren():
            obj["var_ref"] = item.get("var_ref")
        objects.append(obj)


def parse_oval_states(root, ns, states):
    sts = root.find(".//xmlns:states", namespaces=ns)
    for child in sts.getchildren():
        ste = {}
        ste["state_ref"] = child.get("id")
        for item in child.getchildren():
            ste["fixed_version"] = item.text
        states.append(ste)


def parse_oval_variables(root, ns, variables):
    varss = root.find(".//xmlns:variables", namespaces=ns)
    for child in varss.getchildren():
        binpkgs = []
        var = {}
        var["var_ref"] = child.get("id")
        for item in child.getchildren():
            binpkgs.append(item.text)
        var['binaries'] = binpkgs
        variables.append(var)


def parse_args():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('ovalfile', help="input oval filepath")
    argparser.add_argument('jsonfile', help="ouput json filepath")
    return argparser.parse_args()


def main():
    args = parse_args()
    oval_filename = args.ovalfile
    json_filename = args.jsonfile

    parser = ET.XMLParser(ns_clean=True)
    oval = ET.parse(oval_filename, parser)
    root = oval.getroot()
    xmlns = root.nsmap
    xmlns['xmlns'] = xmlns.pop(None)

    data = []
    tests = []
    objects = []
    states = []
    variables = []
    t1 = threading.Thread(target=parse_oval_definitions, args=(root, xmlns, data,))
    t2 = threading.Thread(target=parse_oval_tests, args=(root, xmlns, tests,))
    t3 = threading.Thread(target=parse_oval_objects, args=(root, xmlns, objects,))
    t4 = threading.Thread(target=parse_oval_states, args=(root, xmlns, states,))
    t5 = threading.Thread(target=parse_oval_variables, args=(root, xmlns, variables,))

    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t5.start()

    t1.join()
    t2.join()
    t3.join()
    t4.join()
    t5.join()

    # merge all the data
    for entry in data:
        for test in entry["tests"]:
            for item in tests:
                if item["id"] == test["id"]:
                    test.update(item)
                    break
            for item in objects:
                if item["object_ref"] == test["object_ref"]:
                    test.update(item)
                    break
            if "state_ref" in test:
                for item in states:
                    if item["state_ref"] == test["state_ref"]:
                        test.update(item)
                        break
            if "var_ref" in test:
                for item in variables:
                    if item["var_ref"] == test["var_ref"]:
                        test.update(item)
                        break

    json_formatted = json.dumps(data, indent=2)
    with open(json_filename, "w") as jsonfile:
        jsonfile.write(json_formatted)


if __name__ == "__main__":
    main()
