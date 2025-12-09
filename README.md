# Azure DevOps Advanced Security Alert Downloader

This script pulls Advanced Security alerts (Code, Dependency, Secret) from Azure DevOps for a given repository and branch,
and exports them to a CSV file.

A PAT Token will be required to run the application with the following permissions:

```properties
Advanced Security (READ)
Code (READ)
```

A .env file can be used to set environment variables for convenience.

```properties
ADO_ORG=cantire
ADO_PROJECT=corp-ado-050
ADO_REPO=Demo-GHAzDO_Training
ADO_BRANCH=develop
MAPPED_ADO_PAT=<your_personal_access_token_here>
ADO_API_VERSION=7.2-preview.1
```

## Usage

```shell
python AdvSecAlertDownloader.py --pat PAT --org ORG --project PROJECT --repo REPO [options]
```

### Required

```properties
--pat           Azure DevOps Personal Access Token (or set env MAPPED_ADO_PAT)
--org           Azure DevOps organization name (or set env ADO_ORG)
--project       Azure DevOps project name (or set env ADO_PROJECT)
--repo          Azure DevOps repository name (or set env ADO_REPO)
--branch        Branch name (default: develop, or set env ADO_BRANCH)
--api-version   Azure DevOps API version (default: 7.2-preview.1)
```

### Options

```properties
--pipeline      Pipeline name (optional, or set env ADO_PIPELINE)
-h, --help      Show this help message and exit
```

### Examples

#### Command Line Example

```shell
python AdvSecAlertDownloader.py --org cantire --project corp-ado-050 --repo Demo_GHAzDO-Training --pat <PAT> --api-version 7.2-preview.1
```

#### Command Line with All Repos

```shell
#  Using the --repo all parameter will attempt to download all results for each repository in a project. Requires the branch parameter to be set.
python advSecAlertDownloader.py --org myorg --project myproj --repo all --pat <PAT> --branch develop
```

#### Using .env Example

##### .env Contents

```properties
ADO_ORG=cantire
ADO_PROJECT=corp-ado-050
#ADO_REPO=Demo-GHAzDO_Training
ADO_BRANCH=develop
ADO_API_VERSION=7.2-preview.1
MAPPED_ADO_PAT=C4oyQ.....AZFO2eJQ
```

```shell
python AdvSecAlertDownloader.py --repo Demo_GHAzDO-Training --pipeline Gated_Scan
```
