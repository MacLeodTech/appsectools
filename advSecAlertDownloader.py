
import os
import sys
import requests
import pandas as pd
import argparse
from dotenv import load_dotenv
import json

load_dotenv()
LIGHTBLUE_START = "\033[94m"
GREEN_START = "\033[92m"
YELLOW_START = "\033[93m"
RED_START = "\033[91m"
COLOUR_END = "\033[0m"


def fetch_codeql_alerts(org_name, project, repo, branch, alert_type, pat, api_version, pipeline_name=None):
    url = f"https://advsec.dev.azure.com/{org_name}/{project}/_apis/alert/repositories/{repo}/alerts?api-version={api_version}&orderBy=severity"
    # url += f"?api-version={api_version}&orderBy=severity"
    if branch:
        url += f"&criteria.states=active&criteria.ref={branch}"
    if alert_type:
        url += f"&criteria.alertType={alert_type}"
    if pipeline_name:
        url += f"&criteria.pipelineName={pipeline_name}"
    response = requests.get(url, auth=("", pat))
    response.raise_for_status()
    # except requests.exceptions.HTTPError as e:
    #    print(f"HTTP Error: {e}")
    return response.json().get("value", [])


def list_ado_repositories(org_name, project, pat, api_version):
    url = (
        f"https://dev.azure.com/{org_name}/{project}/_apis/git/repositories?api-version={api_version}")
    response = requests.get(url, auth=("", pat))
    response.raise_for_status()
    repos = response.json().get("value", [])
    return [repo["name"] for repo in repos]


def expand_json_tools(alerts, project, repo):
    results = {}
    alerts_expanded = []
    for alert in alerts:
        x = {}
        x["alertId"] = alert.get("alertId")
        x["tool"] = alert.get("tools", [])[0].get("name")
        x["severity"] = alert.get("severity")
        x["title"] = alert.get("title")
        x["description"] = alert.get("tools", [])[0].get(
            "rules", [])[0].get("description")
        x["gitRef"] = alert.get("gitRef")
        x["alertType"] = alert.get("alertType")
        x["firstSeenDate"] = alert.get("firstSeenDate")
        x["lastSeenDate"] = alert.get("lastSeenDate")
        x["fixedDate"] = alert.get("fixedDate")
        x["introducedDate"] = alert.get("introducedDate")
        x["state"] = alert.get("state")
        x["Secret_TruncatedSecret"] = alert.get("truncatedSecret")
        x["Secret_Confidence"] = alert.get("confidence")
        x["Secret_Validity"] = alert.get("validityDetails")
        x["physicalLocations"] = alert.get("physicalLocations")
        x["resources"] = alert.get("tools", [])[0].get(
            "rules", [])[0].get("resources")
        x["helpMessage"] = alert.get("tools", [])[0].get(
            "rules", [])[0].get("helpMessage")
        x["tags"] = alert.get("tools", [])[0].get("rules", [])[0].get("tags")
        x["additionalProperties"] = alert.get("tools", [])[0].get("rules", [])[
            0].get("additionalProperties")
        x["dismissal"] = alert.get("dismissal")
        x["repositoryURL"] = alert.get("repositoryUrl")
        x["commitHash"] = alert.get("physicalLocations", [])[0].get(
            "versionControl", {}).get("commitHash")
        x["itemUrl"] = alert.get("physicalLocations", [])[0].get(
            "versionControl", {}).get("itemUrl")
        x["filePath"] = alert.get("physicalLocations", [])[0].get("filePath")
        x["region"] = alert.get("physicalLocations", [])[0].get("region")
        x["logicalLocations"] = alert.get("logicalLocations")
        x["opaqueID"] = alert.get("tools", [])[0].get(
            "rules", [])[0].get("opaqueId")
        x["friendlyName"] = alert.get("tools", [])[0].get(
            "rules", [])[0].get("friendlyName")

        alerts_expanded.append(x)
    results["Project"] = project
    results["Repository"] = repo
    results["Alerts"] = alerts_expanded
    return results


def get_alerts(args):
    alert_list = {}
    alert_types = ["Code", "Dependency", "Secret"]
    for alert_type in alert_types:
        try:
            alerts = fetch_codeql_alerts(
                org_name=args.org,
                project=args.project,
                repo=args.repo,
                branch=args.branch,
                alert_type=alert_type,
                pat=args.pat,
                api_version=args.api_version,
                pipeline_name=args.pipeline
            )

            alert_list[alert_type] = expand_json_tools(
                alerts, args.project, args.repo)
#            write_alerts_to_csv(alerts, out_file)
        except requests.exceptions.HTTPError as e:
            # print(f"\t\tHTTP Error: {e}")
            print(
                f"{YELLOW_START}\t[WARN] No {alert_type} alerts found for {args.repo} {args.branch} {args.pipeline}.{COLOUR_END}")
            alert_list[alert_type] = {
                'Project': args.project, 'Repository': args.repo, 'Alerts': []}
        except Exception as e:
            print(
                f"\t[WARN] Failed to fetch or write {alert_type} alerts: {e}")

    return alert_list

# make text yellow :   \033[93m\t
# end text yellow :  \033[0m


def write_csv(alert_list):

    # print(json.dumps(alert_list,indent=2))
    df1 = pd.DataFrame(alert_list["Code"]["Alerts"])
    df2 = pd.DataFrame(alert_list["Dependency"]["Alerts"])
    df3 = pd.DataFrame(alert_list["Secret"]["Alerts"])
    df_combined = pd.concat([df1, df2, df3], ignore_index=True)
    out_file = f"{alert_list['Code']['Project']}--{alert_list['Code']['Repository']}-all-alerts.csv"
    out_file = os.path.join(os.getcwd(), out_file)
    df_combined.to_csv(out_file, index=False)
    print(
        f"{GREEN_START}\t[INFO] Wrote {len(df_combined)} alerts to {out_file}{COLOUR_END}")


def print_help():
    print("""
    Azure DevOps Advanced Security Alert Downloader

    This script pulls Advanced Security alerts (Code, Dependency, Secret) from Azure DevOps for a given repository and branch,
    and exports them to a CSV file.

    A .env file can be used to set environment variables for convenience.
            ``` .env
            ADO_ORG=
            ADO_PROJECT=
            ADO_REPO=Demo
            ADO_BRANCH=develop
            MAPPED_ADO_PAT=<your_personal_access_token_here>
            ADO_API_VERSION=7.2-preview.1
            ```

    Usage:
        python advSecAlertDownloader.py --pat PAT--org ORG --project PROJECT --repo REPO [options]

    Required:
        --pat           Azure DevOps Personal Access Token (or set env MAPPED_ADO_PAT)
        --org           Azure DevOps organization name (or set env ADO_ORG)
        --project       Azure DevOps project name (or set env ADO_PROJECT)
        --repo          Azure DevOps repository name (or set env ADO_REPO)
        --api-version   Azure DevOps API version (default: 7.2-preview.1)
    Options:
        --branch        Branch name (default: develop, or set env ADO_BRANCH)
        --pipeline      Pipeline name (optional, or set env ADO_PIPELINE)
        -h, --help      Show this help message and exit

    Example:
        python advSecAlertDownloader.py --org myorg --project myproj --repo myrepo --pat <PAT>
        
        python advSecAlertDownloader.py --org myorg --project myproj --repo all --pat <PAT> --branch develop
          ** Using the --repo all parameter will attempt to download all results for each repository in a project. Requires the branch parameter to be set.
    """)
    sys.exit(0)


def main():
    # Show help if no arguments or if -h/--help is present
    if any(arg in ("-h", "--help") for arg in sys.argv[1:]):
        print_help()

    parser = argparse.ArgumentParser(
        description="Pull Azure DevOps Advanced Security Alerts and export to CSV.")
    parser.add_argument("--org", default=os.getenv("ADO_ORG"), required=os.getenv(
        "ADO_ORG") is None, help="Azure DevOps organization name (or set env ADO_ORG)")
    parser.add_argument("--project", default=os.getenv("ADO_PROJECT"), required=os.getenv(
        "ADO_PROJECT") is None, help="Azure DevOps project name (or set env ADO_PROJECT)")
    parser.add_argument("--repo", default=os.getenv("ADO_REPO"),
                        help="Azure DevOps repository name (or set env ADO_REPO, optional)")
    parser.add_argument("--branch", default=os.getenv("ADO_BRANCH", "develop"),
                        help="Branch name (default: main, or set env ADO_BRANCH)")
    parser.add_argument("--pat", default=os.getenv("MAPPED_ADO_PAT"),
                        help="Azure DevOps Personal Access Token (or set env MAPPED_ADO_PAT)")
    parser.add_argument("--api-version", default="7.2-preview.1",
                        help="Azure DevOps API version (or set env ADO_API_VERSION)")
    parser.add_argument("--pipeline", default=None,
                        help="Pipeline name (or set env ADO_PIPELINE, optional)")
    parser.add_argument("-o", "--output", default="advsec-results",
                        help="Output directory for results (default: advsec-results)")
    args = parser.parse_args()

    if not args.pat:
        print(
            "[ERROR] Azure DevOps PAT is required. Use --pat or set MAPPED_ADO_PAT in environment.")
        sys.exit(1)

    if not args.project:
        print("[ERROR] Azure DevOps project name is required. Use --project or set ADO_PROJECT in environment.")
        sys.exit(1)

    if not args.repo:
        print("[Error] No repository specified. Listing all alerts for the project is not supported by this script.")
        sys.exit(1)

    if not args.branch:
        args.branch = "develop"

    results_dir = args.output
    print(
        f"{GREEN_START}\t[INFO] Created results directory: {os.path.basename(os.getcwd())}{COLOUR_END}")

    if os.path.basename(os.getcwd()) != results_dir:
        if not os.path.isdir(results_dir):
            os.makedirs(results_dir)
            print(
                f"{GREEN_START}\t[INFO] Created results directory: {results_dir}{COLOUR_END}")
        os.chdir(results_dir)
    print(
        f"{GREEN_START}\t[INFO] Current directory: {os.path.basename(os.getcwd())}{COLOUR_END}")

    # alert_list = get_alerts(args)
    Error_on_Repos = {}
    if args.repo == "all":
        for repo in list_ado_repositories(args.org, args.project, args.pat, args.api_version):
            args.repo = repo
            processing_repo = (f"\n{GREEN_START}Repository: {repo}")
            if args.branch:
                processing_repo += f" | Branch: {args.branch}"
            if args.pipeline:
                processing_repo += f" | Pipeline: {args.pipeline}"
            processing_repo += f"{COLOUR_END}"
            print(processing_repo)

            alert_list = get_alerts(args)
            check = False
            Error_on_Repos[repo] = {}
            Error_on_Repos[repo]["type"] = []
            for alert_type in ["Code", "Dependency", "Secret"]:
                if len(alert_list.get(alert_type, {}).get("Alerts", [])) == 0:

                    Error_on_Repos[repo]["type"].append(alert_type)
                    Error_on_Repos[repo]["branch"] = args.branch
                    Error_on_Repos[repo]["Pipeline"] = args.pipeline

                else:
                    check = True

            if check:
                write_csv(alert_list)
    else:
        alert_list = get_alerts(args)
        write_csv(alert_list)

    if Error_on_Repos:
        print("\nSummary of repositories with no alerts found:")
        print(f"{YELLOW_START}[WARNING] No alerts found for:{COLOUR_END}")
        for k, v in Error_on_Repos.items():
            print(f"{k}:\n\t{v}")


if __name__ == "__main__":
    main()
