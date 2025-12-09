import argparse
import csv
import json
import sys
import os
import re
import requests
from operator import itemgetter
import certifi
import pandas as pd
from colorama import Fore, Style, init


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


def createChartsFromEPSSData(epss_data):

    init(autoreset=True)

    try:
        payload = json.loads(epss_data)
    except Exception as e:
        print(f"Error parsing EPSS JSON: {e}")
        return

    items = payload.get("data", [])
    if not items:
        print("No EPSS data found.")
        return

    rows = []
    for item in items:
        cve = item.get("cve")
        epss_raw = item.get("epss")
        try:
            epss_pct = float(epss_raw) * \
                100 if epss_raw is not None else None
        except Exception:
            epss_pct = None
        rows.append({"cve": cve, "epss_pct": epss_pct})

    df = pd.DataFrame(rows).set_index("cve")
    df = df.sort_values(by="epss_pct", ascending=False, na_position="last")

    # Pretty table header/rows
    col1_w = 25
    col2_w = 10
    sep = "+" + "-" * (col1_w + 2) + "+" + "-" * (col2_w + 2) + "+"

    print(sep)
    print(f"| {'CVE':<{col1_w}} | {'EPSS (%)':>{col2_w}} |")
    print(sep)

    for cve, row in df.iterrows():
        val = row["epss_pct"]
        if val is None or pd.isna(val):
            val_str = "N/A".rjust(col2_w)
            print(f"| {cve:<{col1_w}} | {val_str} |")
            continue

        if val > 10:
            color = Fore.RED
        elif 1 <= val <= 10:
            color = Fore.YELLOW
        else:
            color = ""

        # format value with percent sign and pad to column width before adding color
        val_formatted = f"{val:,.2f}%".rjust(col2_w)
        print(f"| {cve:<{col1_w}} | {color}{val_formatted}{Style.RESET_ALL} |")

    print(sep)


def main():
    if any(arg in ("-h", "--help") for arg in sys.argv[1:]) or len(sys.argv) == 1:
        print_help()
    parser = argparse.ArgumentParser(
        description="Exploit Prediction Scoring System (EPSS) Checker")
    parser.add_argument(
        "-cve", type=str, help="The CVE ID(s) to check (comma separated, no spaces)")
    parser.add_argument(
        "-x", type=str, help="Extract CVEs from a CSV file and check their EPSS")
    args = parser.parse_args()

    if args.cve:
        try:
            epss_data = fetch_epss_data(args.cve)
            # print(json.dumps(json.loads(epss_data), indent=2))
            createChartsFromEPSSData(epss_data)
        except Exception as e:
            print(f"Error: {e}")

    if args.x:
        csv_file = args.x
        if not os.path.isfile(csv_file):
            print(f"Error: File '{csv_file}' does not exist.")
            return
        cves = extract_cves_from_csv(csv_file)
        if cves:
            try:
                epss_data = fetch_epss_data(",".join(cves))
                # print(json.dumps(json.loads(epss_data), indent=2))
                createChartsFromEPSSData(epss_data)
            except Exception as e:
                print(f"Error: {e}")
        else:
            print("No CVEs found in the CSV file.")


if __name__ == "__main__":
    main()
