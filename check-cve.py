#!/usr/bin/env python3
# encoding: utf-8
from optparse import OptionParser
from requests import get
from json import loads
from os.path import isfile
from os.path import getmtime
from time import time
from  json import dump


def check_cve():
    options, args = get_opt()
    product = options.product
    vendor = options.vendor
    if product is None or vendor is None:
        print("You have to specific product and vendor")
        exit()
    search(vendor + "/" + product, options)


# check specific product, vendor, version has cve
def has_cve(data, vendor, product, version, edition):
    vulns = data["vulnerable_configuration"]
    for ele in vulns:
        arr = ele.split(":")
        if vendor in arr and product in arr and version in arr and edition in arr:
            return True
    return False


# check if file modified in the last several days
def check_file_modified(filename, days):
    file_modify_time = getmtime(filename)
    return time() - file_modify_time < (days * 3600 * 1000)


def write_json(filename, result):
    with open(filename, 'w') as f:
        dump(result, f)


def search(params, options):
    url = "https://cve.circl.lu/api/search/" + params
    print(url)
    filename = f"{params.replace('/', '-')}.json"
    try:
        if isfile(filename) and check_file_modified(filename, 3):
            with open(filename, 'r') as f:
                result = loads(f.read())
        else:
            res = get(url)
            if res.status_code == 200:
                with open(filename, 'w') as f:
                    f.write(res.text)
                result = loads(res.text)
            else:
                print("Request failed: %d".format(res.status_code))
        cve_result = []
        for ele in result:
            if has_cve(ele, options.vendor, options.product, options.version, options.edition):
                obj = {
                    "id": ele["id"],
                    "last-modified": ele["last-modified"],
                    "cvss": ele["cvss"],
                    "summary": ele["summary"]
                }
                cve_result.append(obj)
            else:
                continue
        print(f"{options.vendor}:{options.product}:{options.version}:{options.edition} "
              f"has impacted by {len(cve_result)} cve")
        write_json("result.json", cve_result)
    except Exception as e:
        print(e)


def get_opt():
    parser = OptionParser()
    parser.add_option("-p", "--product", dest="product", help="which product")
    parser.add_option("-V", "--vendor", dest="vendor", help="which vendor")
    parser.add_option("-v", "--version", dest="version", help="which version")
    parser.add_option("-e", "--edition", dest="edition", help="which edition")
    (options, args) = parser.parse_args()
    return options, args


if __name__ == '__main__':
    check_cve()

