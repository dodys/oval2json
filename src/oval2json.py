from lxml import etree as ET
import argparse
import json
import sys

XMLNS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
XMLNSOVAL = ""


# definitions are either 'patch' or 'vulnerability' depending on the vendor
def parse_oval_definitions(root, ns, data):
    definitions = root.findall('.//*[@class="patch"]', namespaces=ns)
    if not definitions:
        definitions = root.findall('.//*[@class="vulnerability"]', namespaces=ns)
    for definition in definitions:
        defi = {}
        test = {}
        defi["id"] = definition.get("id")
        print(defi["id"])
        defi["title"] = definition.findtext(".//xmlns:title", namespaces=ns)
        defi["severity"] = definition.findtext(".//xmlns:severity", namespaces=ns)
        defi["tests"] = []
        for criterion in definition.findall(".//xmlns:criteria/xmlns:criterion", namespaces=ns):
            print('criterion')
            test["id"] = criterion.get("test_ref")
            parse_oval_test(root, ns, test, test["id"])
            defi["tests"].append(test)
        data.append(defi)


def parse_oval_test(root, ns, test, test_ref):
    entry = root.find(f".//*[@id='{test_ref}']", namespaces=ns)
    for children in entry.iterchildren():
        if children.get("object_ref"):
            print('test-obj')
            object_ref = children.get("object_ref")
            test["object_ref"] = object_ref
            parse_oval_object(root, ns, test, object_ref)
        elif children.get("state_ref"):
            print('test-state')
            state_ref = children.get("state_ref")
            test["state_ref"] = state_ref
            parse_oval_state(root, ns, test, state_ref)


def parse_oval_object(root, ns, test, object_ref):
    obj = root.find(f".//*[@id='{object_ref}']", namespaces=ns)
    for children in obj.iterchildren():
        print('object')
        var_ref = children.get("var_ref")
        test["var_ref"] = var_ref
        parse_oval_variable(root, ns, test, var_ref)


def parse_oval_state(root, ns, test, state_ref):
    state = root.find(f".//*[@id='{state_ref}']", namespaces=ns)
    for children in state.iterchildren():
        print('state')
        version = children.text
        test["fixed_version"] = version


def parse_oval_variable(root, ns, test, var_ref):
    binpkgs = []
    values = root.findall(f".//*[@id='{var_ref}']/xmlns:value", namespaces=ns)
    for val in values:
        print('var')
        binpkgs.append(val.text)
    test['binaries'] = binpkgs


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
    parse_oval_definitions(root, xmlns, data)
    json_formatted = json.dumps(data, indent=2)
    with open(json_filename, "w") as jsonfile:
        jsonfile.write(json_formatted)


if __name__ == "__main__":
    main()


#filename = 'com.ubuntu.bionic.usn.oval.xml'
#parser = ET.XMLParser(ns_clean=True)
#oval   = ET.parse(filename, parser)
#root = oval.getroot()
#xmlns = root.nsmap
#xmlns['xmlns'] = xmlns.pop(None)
#testref = ""
#for defi in root.find(".//definitions", namespaces=root.nsmap):
#    if defi.get('class') == "patch":
#        for crit in defi.findall(".//criterion", namespaces=root.nsmap):
#            testref = crit.get('test_ref')
#
#print(testref)
#
#data = {}
#version = ""
#binpkgs = []
#definitions = root.xpath('//*[@class="patch"]', namespaces=xmlns)
#if not definitions:
#    definitions = root.xpath('//*[@class="vulnerability"]', namespaces=xmlns)
#for definition in definitions:
#    def_id = definition.get('id')
#    data[def_id] = {'test_refs': []}
#    data[def_id]['object_refs'] = []
#    data[def_id]['state_refs'] = []
#    data[def_id]['var_ref'] = []
#    for criterion in definition.findall('.//xmlns:criteria/xmlns:criterion', namespaces=xmlns):
#        test_ref = criterion.get('test_ref')
#        object_ref = ""
#        state_ref = ""
#        var_ref = ""
#        data[def_id]['test_refs'].append(test_ref)
#        tests = root.xpath(f"//*[@id='{test_ref}']", namespaces=xmlns)
#        test = tests[0]
#        for children in test.iterchildren():
#            if children.get('object_ref'):
#                object_ref = children.get('object_ref')
#                data[def_id]['object_refs'].append(object_ref)
#            elif children.get('state_ref'):
#                state_ref = children.get('state_ref')
#                data[def_id]['state_refs'].append(state_ref)
#        objects = root.xpath(f"//*[@id='{object_ref}']", namespaces=xmlns)
#        obj = objects[0]
#        for children in obj.iterchildren():
#            var_ref = children.get('var_ref')
#            data[def_id]['var_ref'].append(var_ref)
#        states = root.xpath(f"//*[@id='{state_ref}']", namespaces=xmlns)
#        ste = states[0]
#        for children in ste.iterchildren():
#            version = children.text
#        values = root.xpath(f"//*[@id='{var_ref}']/xmlns:value", namespaces=xmlns)
#        for val in values:
#            binpkgs.append(val.text)
#
#print(data)
#print(version)
#print(binpkgs)


