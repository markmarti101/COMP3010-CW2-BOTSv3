## Overview

This repository contains a Security Operations Center (SOC)-style investigation of a simulated security incident using the Boss of the SOC v3 (BOTSv3) dataset and Splunk. The BOTSv3 dataset is a fully simulated security incident that occurred within a fake company called "Frothly" and provides logs from several data sources, such as AWS. This project only looks at AWS-related information (CloudTrail and S3 access) and selected endpoint telemetry to identify misconfigured resources or suspicious activity, while serving as a way to document the investigation with Splunk's SPL.

## Repository Structure

- `README.md` - This document and the summary of the entire project
- `screenshots/` - Evidence images for each guided question.
- `queries/` - Saved SPL queries (this folder is optional for this course but is recommended).

## Goals of the Project

The purpose of this project is to accomplish the following goals:

1. Install Splunk and ingest the BOTSv3 dataset, ensuring data sources can be searched within Splunk.
2. Answer a complete set (one full set) of 200-level guided questions with corresponding evidence (queries, screenshots, and reasoning), through the use of SPL.
3. Consider the SOC roles and incident handling methods (detection, analysis, response, and recovery) based on the findings from the BOTSv3 dataset.

**Project Scope:** AWS service access; IAM activity (IAM users accessing AWS services), S3 bucket access controls (ability to upload), and anomalous/firewall activity of endpoints or hosts (operating systems).

**Assumptions:** All findings based on this project are from the BOTSv3 dataset and only reflect the simulated nature of Frothly.

---

## Environment Setup and Data Validation

### Splunk Environment

Splunk Enterprise was utilised as the analysis tool for this project. Access to the Splunk web interface was available locally on port `8000`, and searches were performed using the **Search & Reporting** app.

### Installation of the BOTSv3 Dataset

The BOTSv3 dataset archive (`botsv3_data_set.tar`) was extracted into the respective Splunk apps directory, after which Splunk was restarted to load the BOTSv3 dataset.

### Validating The Dataset

To confirm the dataset has been loaded correctly into Splunk, I performed the following validation searches:
- `index=botsv3 | stats count`
- `index=botsv3 | stats count by sourcetype | sort -count`

I created the corresponding evidence screenshots for the initial setup and ingestion under the `screenshots/ingestion/` directory.

---

### Guided Questions (AWS / CloudTrail)

### Q1 - IAM Users Using AWS Services

**Task:** Identify the IAM users that successfully (or unsuccessfully) accessed AWS services in the Frothly AWS environment.   

**Data Source:** `sourcetype=aws:cloudtrail`   

**Approach:** Filter the CloudTrail events to only IAM users and then list the unique usernames.

**SPL Use:**
```spl
index=botsv3 sourcetype=aws:cloudtrail
| search userIdentity.type=IAMUser
| stats values(userIdentity.userName) as iam_users
| eval iam_users=mvsort(iam_users)
| eval iam_users=mvjoin(iam_users, ",")
```

####Answer:
```
bstoll,btun,splunk_access,web_admin
```

### Q2 - AWS API Calls Without MFA

**Task:** Identify the CloudTrail field that will be used to monitor AWS API calls that are made without MFA. 
ConsoleLogin events will be excluded based on the question's guidance.

**Data Source:** `sourcetype=aws:cloudtrail`

####Method
An analysis of the AWS CloudTrail logs was conducted to identify any MFA-related attributes associated with AWS API calls. A keyword search for MFA was performed and all ConsoleLogin events were explicitly excluded to ensure only API-level activity was investigated. The remaining API events were analysed to identify which CloudTrail field captured whether MFA was used during authentication.

####The following SPL was used for this investigation:
```spl
index=botsv3 sourcetype=aws:cloudtrail
| search *MFA*
| search NOT eventName=ConsoleLogin
| table eventName userIdentity.sessionContext.attributes.mfaAuthenticated
```

####Answer:

```
userIdentity.sessionContext.attributes.mfaAuthenticated
```

### Q3 – Web Server Processor Information

**Task:** Identify the processor number used on Frothly’s web servers.  
**Data source:** `sourcetype=hardware`  
**Approach:** Query hardware inventory data for web server hosts and extract CPU model information.

**SPL used:**
```spl
index=botsv3 sourcetype=hardware
| search host=gacrux*
| table host cpu_type
```

####Answer:

```
Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz
```

### Q4 – Publicly Accessible S3 Bucket (PutBucketAcl)

**Task:** Identify the event ID of the API call that enabled public access on an S3 bucket.  
**Data source:** `sourcetype=aws:cloudtrail`  
**Approach:** Search CloudTrail for the `PutBucketAcl` event, then inspect the event details to determine which ACL change introduced public permissions. Although multiple `PutBucketAcl` events exist, only one enabled public access.

**SPL used:**
```spl
index=botsv3 sourcetype=aws:cloudtrail
| search eventName=PutBucketAcl
| table _time eventID eventName eventSource userIdentity.type userIdentity.userName userIdentity.sessionContext.sessionIssuer.userName requestParameters
```

####Answer:
```
ab45689d-69cd-41e7-8705-5350402cf7ac
```

### Q5 – Bud’s IAM Username
**Task:** Identify the IAM username associated with Bud.

**Data source:** `sourcetype=aws:cloudtrail`  
**Approach:** Search CloudTrail events related to S3 ACL changes and extract the IAM username.

**SPL used:**
```spl
index=botsv3 sourcetype=aws:cloudtrail
| search eventName=PutBucketAcl
| stats values(userIdentity.userName) as usernames
```

####Answer:
```
bstoll
```

### Q6 – Publicly Accessible S3 Bucket Name
**Task:** Identify the name of the S3 bucket that was made publicly accessible.

**Data source:** `sourcetype=aws:cloudtrail`  
**Approach:** Locate the `PutBucketAcl` API call and extract the bucket name from the request parameters.

**SPL used:**
```spl
index=botsv3 sourcetype=aws:cloudtrail
| search eventName=PutBucketAcl
| table _time userIdentity.userName requestParameters.bucketName eventID
```

####Answer:
```
frothlywebcode
```

###Q7 – Text File Uploaded to Public S3 Bucket
**Task**: Identify the text file that was successfully uploaded to the publicly accessible S3 bucket (frothlywebcode).

**Data source**: sourcetype=aws:s3:accesslogs
**Approach**: Filter S3 access logs for successful REST.PUT.OBJECT uploads (HTTP 200 or 204) to the bucket frothlywebcode. Extract the PUT URI from the raw log, derive the uploaded filename, and restrict results to .txt.

**SPL used:**
```spl
index=botsv3 sourcetype="aws:s3:accesslogs" "REST.PUT.OBJECT"
| rex field=_raw "^\S+\s+(?<bucket>\S+).+?\"PUT\s+(?<uri>/[^ ]+)\s+HTTP"
| rex field=_raw "\"\s+(?<http_status>\d{3})\s"
| search bucket="frothlywebcode" http_status IN ("200","204")
| eval file=replace(uri,".*/","")
| search file="*.txt"
| table _time bucket http_status uri file
| sort _time
```

####Answer:
```
OPEN_BUCKET_PLEASE_FIX.txt
```

###Q8 – Endpoint Running a Different Windows Operating System Edition

**Task**: Identify the FQDN of the endpoint that is running a different Windows operating system edition than the other Windows hosts in the Frothly environment.
**Data source**: sourcetype=WinHostMon

**Approach**:
To identify Windows operating system editions across endpoints, Windows host monitoring data was analysed using the winhostmon source type. Initial keyword searches for windows, operating system, and edition helped determine that OS inventory information is stored in Type=OperatingSystem events.
The OS field within these events clearly indicates the Windows edition running on each host. By aggregating and counting operating system editions per host, and then summing counts per OS, the least common Windows edition was identified as an outlier. The host associated with this outlier OS was then converted to its fully qualified domain name (FQDN).

**SPL used:**
```spl
index=botsv3 sourcetype=WinHostMon Type=OperatingSystem
| stats count by host OS
| eventstats sum(count) as total_by_os by OS
| where OS="Microsoft Windows 10 Enterprise"
| eval fqdn=lower(host).".froth.ly"
| table fqdn OS total_by_os
```

####Answer:
```
bstoll-l.froth.ly
```
