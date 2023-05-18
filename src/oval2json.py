import xml.etree.ElementTree as ET
import argparse
import json
import sys
import threading
import yaml

xmlns = {
    'xmlns': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
    'oval': 'http://oval.mitre.org/XMLSchema/oval-common-5',
    'ind-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent',
    'unix-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#unix',
    'linux-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
}

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
        defi["cves"] = []
        cves = definition.findall(".//xmlns:cve", namespaces=ns)
        tests = definition.findall(".//xmlns:criteria/xmlns:criterion", namespaces=ns)
        j = 0
        for i in range(len(tests)):
            cve_id = cves[j].text
            if cve_id in tests[i].get("comment"):
                defi["cves"].append(
                    {
                        "cve_id": cves[j].text,
                        "public_date": cves[j].get("public"),
                        "severity": cves[j].get("severity"),
                        "cvss_score": cves[j].get("cvss_score"),
                        "cvss_vector": cves[j].get("cvss_vector"),
                        "test_ref": tests[i].get("test_ref"),
                    }
                )
                j = j + 1
        data.append(defi)


def parse_oval_tests(root, ns, tests):
    tsts = root.find(".//xmlns:tests", namespaces=ns)
    for child in tsts:
        tst = {}
        tst["test_ref"] = child.get("id")
        for item in child:
            if item.get("object_ref"):
                tst["object_ref"] = item.get("object_ref")
            elif item.get("state_ref"):
                tst["state_ref"] = item.get("state_ref")
        tests.append(tst)


def parse_oval_objects(root, ns, objects):
    objs = root.find(".//xmlns:objects", namespaces=ns)
    for child in objs:
        obj = {}
        obj["object_ref"] = child.get("id")
        for item in child:
            if item.get("var_ref"):
                obj["var_ref"] = item.get("var_ref")
            else:
                obj["var_ref"] = item.text
        objects.append(obj)


def parse_oval_states(root, ns, states):
    sts = root.find(".//xmlns:states", namespaces=ns)
    for child in sts:
        ste = {}
        ste["state_ref"] = child.get("id")
        for item in child:
            ste["fixed_version"] = item.text
        states.append(ste)


def parse_oval_variables(root, ns, variables):
    varss = root.find(".//xmlns:variables", namespaces=ns)
    for child in varss:
        binpkgs = []
        var = {}
        var["var_ref"] = child.get("id")
        for item in child:
            if child.get("datatype") != "string":
                var["fixed_version"] = item.text
            else:
                binpkgs.append(item.text)
        var["binaries"] = binpkgs
        variables.append(var)


# TODO: this still feels hack-ish, should try to make it
# smarter and faster
def merge_dicts(data, tests, objects, states, variables):
    for entry in data:
        for cve in entry["cves"]:
            for item in tests:
                if item["test_ref"] == cve["test_ref"]:
                    cve.update(item)
                    break
            for item in objects:
                if item["object_ref"] == cve["object_ref"]:
                    cve.update(item)
                    break
            if "state_ref" in cve:
                for item in states:
                    if item["state_ref"] == cve["state_ref"]:
                        cve.update(item)
                        break
            if "var_ref" in cve:
                for item in variables:
                    if item["var_ref"] == cve["var_ref"]:
                        cve.update(item)
                        break


def parse_args():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("ovalfile", help="input OVAL filepath")
    argparser.add_argument("jsonfile", help="ouput JSON filepath")
    argparser.add_argument(
        "--yaml", action="store_true", help="generate output also in YAML format"
    )
    return argparser.parse_args()


def main():
    args = parse_args()
    oval_filename = args.ovalfile
    json_filename = (
        args.jsonfile + ".json" if ".json" not in args.jsonfile else args.jsonfile
    )
    yaml_filename = ""
    if args.yaml:
        yaml_filename = json_filename.replace(".json", ".yaml")

    oval = ET.parse(oval_filename)
    root = oval.getroot()

    data = []
    tests = []
    objects = []
    states = []
    variables = []
    t1 = threading.Thread(
        target=parse_oval_definitions,
        args=(
            root,
            xmlns,
            data,
        ),
    )
    t2 = threading.Thread(
        target=parse_oval_tests,
        args=(
            root,
            xmlns,
            tests,
        ),
    )
    t3 = threading.Thread(
        target=parse_oval_objects,
        args=(
            root,
            xmlns,
            objects,
        ),
    )
    t4 = threading.Thread(
        target=parse_oval_states,
        args=(
            root,
            xmlns,
            states,
        ),
    )
    t5 = threading.Thread(
        target=parse_oval_variables,
        args=(
            root,
            xmlns,
            variables,
        ),
    )

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

    merge_dicts(data, tests, objects, states, variables)

    json_formatted = json.dumps(data, indent=2)
    with open(json_filename, "w") as jsonfile:
        jsonfile.write(json_formatted)

    if args.yaml:
        with open(yaml_filename, "w") as yamlfile:
            yaml.dump(data, yamlfile, sort_keys=False)


if __name__ == "__main__":
    main()
