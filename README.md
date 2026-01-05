## Introduction
This repository contains a professional SOC-style investigation using Splunk and the Boss of the SOC v3 (BOTSv3) dataset. BOTSv3 simulates a realistic security incident inside a fictitious company (“Frothly”) and includes logs from multiple sources. In this coursework I focus on AWS-related events (CloudTrail and S3 access logs) and selected endpoint telemetry to identify misconfigurations and suspicious activity, then document the investigation using Splunk SPL.

## Repository Contents
- `README.md` – Main report (this file)
- `screenshots/` – Evidence images for each guided question
- `queries/` – Saved SPL queries (optional but recommended)

## Objectives
The objectives of this investigation are:
1. Install Splunk, ingest BOTSv3, and validate that data sources are searchable.
2. Use SPL to answer one full set of 200-level guided questions with clear evidence (queries, screenshots, and reasoning).
3. Reflect on SOC roles and incident handling processes (detection, analysis, response, recovery) based on what the BOTSv3 findings demonstrate.

**Scope:** AWS service access, IAM activity, S3 bucket access controls/uploads, and endpoint OS/host anomalies.  
**Assumptions:** Findings are derived only from the BOTSv3 dataset and reflect the simulated Frothly environment.

---

## Environment Setup and Data Validation

### Splunk Environment
Splunk Enterprise was used as the analysis platform. Splunk Web was accessed locally on port `8000` and searches were performed using the **Search & Reporting** app.

### BOTSv3 Dataset Installation
The BOTSv3 pre-indexed dataset archive (`botsv3_data_set.tar`) was extracted into Splunk’s apps directory and Splunk was restarted to load the dataset.

### Dataset Validation
To confirm the dataset loaded successfully, the following validation searches were used:
- `index=botsv3 | stats count`
- `index=botsv3 | stats count by sourcetype | sort -count`

Evidence screenshots for setup and ingestion are stored in `screenshots/ingestion/`.

---

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


