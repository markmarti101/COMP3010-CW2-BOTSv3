## Overview

The intention of this repository is to provide a professional SOC-style investigation through the usage of Splunk and the BOTSv3 (Boss of the SOC version 3) dataset. BOTSv3 acts as a simulation of a true security breach that has occurred inside a made-up company (“Frothly”). It incorporates logs that consist of many different sources. In this coursework, I have concentrated on AWS Events (CloudTrail and S3 Access Logs) along with endpoint telemetry, whereby my task is to analyse these logs for misconfigurations or suspicious activity and to document my investigation in the form of a report generated using the Splunk SPL (Search Processing Language).

## Repository Contents

* README.md: The main deliverable for this project.
* screenshots/: All the screenshots of the evidence collected in response to each of the guided 200-level questions.
* queries/: A collection of saved SPL Queries that I created throughout my investigation (highly encouraged, but optional)

## Objectives 

The objectives of this investigation are: 
1. Install the Splunk Enterprise software, ingest the BOTSv3 data set and confirm all data sources are searchable.
2. Use SPL to complete one complete set of 200-level guided questions, providing supporting evidence to my responses consisting of queries, screenshots, and reasoning.
3. Evaluate the SOC Roles and Incident Handling (Detection, Analysis, Response and Recovery) processes based on the findings from the BOTSv3 dataset.

Scope: Access to AWS services (IAM) and access to and uploads into S3 buckets as well as OS/Host anomalies from endpoints.
Assumptions: All information/data has been provided from the BOTSv3 dataset and is based on the environment created by the simulation of Frothly.

## Environment Setup and Data Validation 

## Splunk Environment 

I used Splunk Enterprise as my analysis platform for completing the investigation. I accessed Splunk Web locally on Port 8000 and performed all my searches through the Search and Reporting app.

## BOTSv3 Data Set Installation 

I extracted the pre-indexed BOTSv3 dataset archive from the supplied `botsv3_data_set.tar` file into the apps directory of Splunk, then restarted Splunk to load the dataset into the application.

### Dataset Validation
To confirm the dataset loaded successfully, the following validation searches were used:
- `index=botsv3 | stats count`
- `index=botsv3 | stats count by sourcetype | sort -count`

Evidence screenshots for setup and ingestion are stored in `screenshots/ingestion/`.


## Guided Questions (AWS / CloudTrail)

### Q1 – IAM Users Accessing AWS Services
**Task:** Identify IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly’s AWS environment.  
**Data source:** `sourcetype=aws:cloudtrail`  
**Approach:** Filter CloudTrail events to IAM users and list unique usernames.

**SPL used:**
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

### Q2 – AWS API Activity Without MFA
**Task:** Identify the CloudTrail field that can be used to alert on AWS API activity occurring without multi-factor authentication (MFA). Console login events were excluded as per the question guidance.  
**Data source:** `sourcetype=aws:cloudtrail`

#### Method
AWS CloudTrail logs were analysed to identify MFA-related attributes associated with AWS API calls. A keyword search for MFA was performed and `ConsoleLogin` events were explicitly excluded to ensure only API-level activity was examined. The resulting events were inspected to determine which CloudTrail field records whether MFA was used during authentication.

#### SPL Used
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

## Video Walkthrough
YouTube video: https://www.youtube.com/watch?v=Uxsl3QHe_D0
