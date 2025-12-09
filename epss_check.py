import argparse
import csv
import json
import sys
import os
import re
import requests
from operator import itemgetter
import certifi


def print_help():
    print(f"""
        Exploit Prediction Scoring System Checker
          
        EPSS Home: https://www.first.org/epss/
        EPSS FAQ: https://www.first.org/epss/faq
        EPSS Stats: https://www.first.org/epss/data_stats
        
          
        The Exploit Prediction Scoring System (EPSS) estimates 
        the likelihood that a software vulnerability will be 
        exploited in the wild.
        
        Usage: check [options]
        
            ex. check -cve=CVE-2022-27225,CVE-2025-1536,CVE-2024-40891
            ex. check -csv=./test.csv
        
        Required Option:
        
          -cve     The CVE ID(s) to check: One or More Comma Separated List without spaces.
          -extract Extract CVEs from a CSV file and check their EPSS.
          -x       Extract CVEs from a CSV file and check their EPSS.
          -help    Show usage information.
              
          """)
    return 0


def fetch_epss_data(cves):
    if not cves:
        raise ValueError("CVE list cannot be empty")

    base_url = "https://api.first.org/data/v1/epss"
    params = {"cve": cves}

    try:
        # TODO: Handle SSL verification properly in production code
        # , verify=certifi.where())#"assets/api.first.org.pem")
        response = requests.get(base_url, params=params, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise RuntimeError(f"Error fetching EPSS data: {e}")


def extract_cves_from_csv(file_path):
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
    cves = set()

    with open(file_path, 'r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            for item in row:
                matches = cve_pattern.findall(item)
                cves.update(matches)

    return list(cves)


def main():
    if any(arg in ("-h", "--help") for arg in sys.argv[1:]) or len(sys.argv) == 1:
        print_help()
    parser = argparse.ArgumentParser(
        description="Exploit Prediction Scoring System (EPSS) Checker")
    parser.add_argument(
        "-cve", type=str, help="The CVE ID(s) to check (comma separated, no spaces)")
    parser.add_argument("-x", "-extract", type=str,
                        help="Extract CVEs from a CSV file and check their EPSS")
    args = parser.parse_args()

    if args.cve:
        try:
            epss_data = fetch_epss_data(args.cve)
            print(epss_data)
        except Exception as e:
            print(f"Error: {e}")

    if args.x or args.extract:
        csv_file = args.x if args.x else args.extract
        if not os.path.isfile(csv_file):
            print(f"Error: File '{csv_file}' does not exist.")
            return
        cves = extract_cves_from_csv(csv_file)
        if cves:
            try:
                epss_data = fetch_epss_data(",".join(cves))
                print(json.dumps(json.loads(epss_data), indent=2))
            except Exception as e:
                print(f"Error: {e}")
        else:
            print("No CVEs found in the CSV file.")


if __name__ == "__main__":
    main()
