## Introduction
This repository contains a professional SOC-style investigation using Splunk and the Boss of the SOC v3 (BOTSv3) dataset. BOTSv3 simulates a realistic security incident inside a fictitious company (“Frothly”) and includes logs from multiple sources. In this coursework I focus on AWS-related events (CloudTrail and S3 access logs) and selected endpoint telemetry to identify misconfigurations and suspicious activity, then document the investigation using Splunk SPL.

## Repository Contents
- `README.md` – Main report (this file)
- `screenshots/` – Evidence images for each guided question
- `queries/` – Saved SPL queries (optional but recommended)


The objectives of this investigation are:
1. Install Splunk, ingest BOTSv3, and validate that data sources are searchable.
2. Use SPL to answer one full set of 200-level guided questions with clear evidence (queries, screenshots, and reasoning).
3. Reflect on SOC roles and incident handling processes (detection, analysis, response, recovery) based on what the BOTSv3 findings demonstrate.

**Scope:** AWS service access, IAM activity, S3 bucket access controls/uploads, and endpoint OS/host anomalies.  
**Assumptions:** Findings are derived only from the BOTSv3 dataset and reflect the simulated Frothly environment.
