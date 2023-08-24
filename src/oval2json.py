import xml.etree.ElementTree as ET
import argparse
import json
import re
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
def parse_oval_definitions(root, ns, definitions):
    defs = root.findall('.//*[@class="patch"]', namespaces=ns)
    if not defs:
        defs = root.findall('.//*[@class="vulnerability"]', namespaces=ns)

    for defi in defs:
        key = defi.get("id")
        definitions[key] = {}
        definitions[key]["title"] = defi.findtext(
            ".//xmlns:title", namespaces=ns
        )
        definitions[key]["description"] = defi.findtext(
            ".//xmlns:description", namespaces=ns
        )
        definitions[key]["severity"] = defi.findtext(
            ".//xmlns:severity", namespaces=ns
        )

        issued = defi.find(".//xmlns:issued", namespaces=ns)
        if issued:
            definitions[key]["issued"] = issued.get("date")

        definitions[key]["reference"] = []
        for ref in defi.findall(".//xmlns:reference", namespaces=ns):
            definitions[key]["reference"].append(ref.attrib)
        definitions[key]["cves"] = []
        for cve in defi.findall(".//xmlns:cve", namespaces=ns):
            definitions[key]["cves"].append(
                {
                    "cve_id": cve.text,
                    "public_date": cve.get("public"),
                    "severity": cve.get("severity"),
                    "cvss_score": cve.get("cvss_score"),
                    "cvss_vector": cve.get("cvss_vector"),
                }
            )
        definitions[key]["test_refs"] = {}
        for test in defi.findall(
            ".//xmlns:criteria/xmlns:criterion", namespaces=ns
        ):
            test_ref = test.get("test_ref")
            definitions[key]["test_refs"][test_ref] = {}
            definitions[key]["test_refs"][test_ref]["comment"] = test.get("comment")


def parse_oval_tests(root, ns, tests):
    tsts = root.find(".//xmlns:tests", namespaces=ns)
    for test in tsts:
        key = test.get("id")
        tests[key] = {}
        for item in test:
            if item.get("object_ref"):
                tests[key]["object_ref"] = item.get("object_ref")
            elif item.get("state_ref"):
                tests[key]["state_ref"] = item.get("state_ref")


def parse_oval_objects(root, ns, objects):
    objs = root.find(".//xmlns:objects", namespaces=ns)
    for obj in objs:
        key = obj.get("id")
        objects[key] = {}
        for item in obj:
            if item.get("var_ref"):
                objects[key]["var_ref"] = item.get("var_ref")
            elif "var_ref" in item.tag:
                objects[key]["var_ref"] = item.text


def parse_oval_states(root, ns, states):
    sts = root.find(".//xmlns:states", namespaces=ns)
    for ste in sts:
        key = ste.get("id")
        states[key] = {}
        for item in ste:
            states[key]["fixed_version"] = item.text


def parse_oval_variables(root, ns, variables):
    varss = root.find(".//xmlns:variables", namespaces=ns)
    for var in varss:
        binpkgs = []
        key = var.get("id")
        variables[key] = {}
        for item in var:
            result = re.search(r'^(?:\^)(.*)(?:\(\?.*)', item.text)
            if result:
                binary = re.sub(r'\\', '', result[1])
                binpkgs.append(binary)
            else:
                binpkgs.append(item.text)
        variables[key]["binaries"] = binpkgs


def merge_dicts(definitions, tests, objects, states, variables):
    for key in definitions.keys():
        for ref, val in definitions[key]["test_refs"].items():
            test_id = ref
            obj_id = tests[test_id]["object_ref"]
            val["object_ref"] = obj_id
            if "state_ref" in tests[test_id]:
                ste_id = tests[test_id]["state_ref"]
                val["state_ref"] = ste_id
                val["fixed_version"] = states[ste_id]["fixed_version"]
            if "var_ref" in objects[obj_id]:
                var_id = objects[obj_id]["var_ref"]
                val["var_ref"] = var_id
                val["binaries"] = variables[var_id]["binaries"]


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

    definitions = {}
    tests = {}
    objects = {}
    states = {}
    variables = {}
    t1 = threading.Thread(
        target=parse_oval_definitions,
        args=(
            root,
            xmlns,
            definitions,
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

    merge_dicts(definitions, tests, objects, states, variables)

    json_formatted = json.dumps(definitions, indent=2)
    with open(json_filename, "w") as jsonfile:
        jsonfile.write(json_formatted)

    if args.yaml:
        with open(yaml_filename, "w") as yamlfile:
            yaml.dump(definitions, yamlfile, sort_keys=False)


if __name__ == "__main__":
    main()
