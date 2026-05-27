# Sourcetype Analysis Prompt

I have a CSV file of Splunk sourcetypes (typically with event counts from a `tstats` search) that need to be analyzed and classified for CIM normalization. Please create a comprehensive analysis CSV file matching the master inventory schema described below.

## Output Columns (in this exact order)

| # | Column | Description |
|---|--------|-------------|
| 1 | `sourcetype` | The sourcetype name |
| 2 | `scope` | One of: `security`, `operational`, `security,operational`, `none`, `unknown` |
| 3 | `security_classification` | Acronym(s) from `security_classifications_reference.md` ONLY (e.g., EDR, NGFW, IAM). Leave blank for non-security sourcetypes. List up to 3 if applicable, comma-separated. |
| 4 | `security_relevance` | One of: `none`, `low`, `med`, `high` |
| 5 | `data_models` | Up to 3 CIM data models in `Model.Dataset` format (e.g., `Authentication.Authentication`, `Network_Traffic.All_Traffic`). Use ONLY models/datasets that exist in the latest `splunk_data_model_objects_fields_xxx.csv` reference file. Comma-separated. |
| 6 | `vendor` | Technology vendor(s); blank if unknown/not applicable. Multiple vendors only when you're highly confident about the association. |
| 7 | `description` | Short label, ~50 characters max (e.g., `Akamai SIEM connector events`) |
| 8 | `expanded_desc` | Detailed description, 15-30 words — what the log contains, key fields, delivery mechanism, CIM data models it feeds |
| 9 | `exclude` | `N` for all new entries (use `Y` only if known to be junk/internal noise) |
| 10 | `exclude_reason` | Blank unless `exclude=Y` |
| 11 | `reviewed_by` | Reviewer label: `AI Analysis` for AI-generated rows, `MDI Reference` for curated MDI reference rows, or a reviewer email for human-curated rows |
| 12 | `reviewed_date` | Today's date in `M/D/YYYY` format |
| 13 | `provenance` | One of: `human_curated`, `ai_generated`, `imported_from_<source>`. Use `human_curated` only after a human pass. |

**Note on the `events` column:** If the input CSV contains event counts, keep `events` only in your working copy. Drop it before merging into the master inventory — the master does not preserve event counts.

**Output sort order:** Sort the output by `vendor` (ascending) then `sourcetype` (ascending). The master inventory uses this ordering and merges are easier when both sides match.

## Reference Files — Source of Truth (do NOT make anything up)

These two files are authoritative. Every value you put in `security_classification` and `data_models` MUST come from them.

1. **`security_classifications_reference.md`** — the authoritative list of security classification acronyms (EDR, NGFW, IAM, SIEM, WAF, VPN, PAM, MFA, IDS, IPS, SOAR, CASB, SWG, ESG, EPP, etc.) with descriptions, vendor examples, and classification guidance. Reference this file for every `security_classification` value. If a security technology doesn't clearly match an acronym in this file, leave `security_classification` blank rather than inventing one.

2. **`splunk_data_model_objects_fields_<version>.csv`** (the latest version in the repo — currently `splunk_data_model_objects_fields_850.csv` for CIM 8.5.0) — the authoritative list of CIM data models, datasets, and fields. Every `data_models` entry MUST be a `Model.Dataset` pair that exists in this file. Default to the latest version unless you specifically need to target an environment pinned to an older CIM release.

## Critical Requirements

- Work through ALL sourcetypes systematically — do not skip any entries
- Take your time with each sourcetype — carefully analyze what it represents before assigning classifications
- Match the master schema exactly (column order, count, value formats)

## Data Model Mapping Accuracy

- Reference the latest `splunk_data_model_objects_fields_xxx.csv` for ALL data model assignments
- Do NOT make up or assume data models — only use `Model.Dataset` pairs that exist in the reference file
- Prioritize data models from most specific to least specific (up to 3 maximum)
- Consider what fields the sourcetype likely contains and which data models those fields map to
- Examples:
  - authentication logs → `Authentication.Authentication`
  - firewall traffic → `Network_Traffic.All_Traffic`, `Intrusion_Detection.IDS_Attacks` (if threat data present)
  - WAF logs → `Web.Web`, `Alerts.Alerts`
  - file integrity → `Change.All_Changes`
  - DNS query logs → `Network_Resolution.DNS`
- If no CIM data model applies (pure ops/performance logs), leave `data_models` blank

## Security Classification Accuracy

- Reference `security_classifications_reference.md` for ALL classifications
- Think about the primary security function of the technology
- For multi-function devices (e.g., NGFW with IPS), list multiple classifications
- Leave `security_classification` blank when `scope` is purely operational

## Security Relevance Guidelines

- **High**: Direct threat detection, authentication/authorization, vulnerability data, security alerts
- **Med**: Audit logs, configuration changes, access logs, compliance data
- **Low**: Inventory, informational logs, package management
- **None**: Pure performance metrics, statistics with no security value

## Scope Guidelines

- **security**: Primary purpose is security monitoring/detection
- **operational**: Primary purpose is system/application performance, availability, inventory
- **security,operational**: Serves both purposes equally (rare — be selective)
- **unknown**: Insufficient information to determine

## Vendor Identification — Common Naming-Prefix Patterns

When the sourcetype starts with a vendor-specific prefix or matches a well-known add-on naming convention, the vendor is almost always identifiable. Be conservative — leave `vendor` blank rather than guessing.

| Prefix / pattern | Vendor |
|------------------|--------|
| `aws:*`, `amazon:*`, `amazon-*`, `am:cw:*`, `app:rds:*` | Amazon Web Services |
| `azure:*`, `ms:o365:*`, `o365:*`, `ms:wmi:*`, `WinEventLog:*`, `XmlWinEventLog:*`, `MSAD:*` | Microsoft |
| `google:gcp:*`, `gcp:*`, `gws:*` | Google Cloud Platform |
| `cisco:*` | Cisco |
| `crowdstrike:*`, `falcon:*` | CrowdStrike |
| `tsc:*`, `tenable:*`, `nessus:*` | Tenable |
| `sap:*` | SAP |
| `snow:*`, `servicenow` | ServiceNow |
| `pan:*` | Palo Alto Networks |
| `fgt_*`, `fortigate:*`, `fortinet:*` | Fortinet |
| `juniper:*` | Juniper Networks |
| `okta:*` | Okta |
| `linux_*`, `osquery*`, `syslog`, `auditd` | Linux/OS-level (vendor may be the distro or "Linux") |
| `splunkd*`, `splunk_audit*`, `splunk:*` | Splunk |
| `vmware:*`, `vmware-*` | VMware |

## `expanded_desc` Style Guide

- 15-30 words target length
- State what the log records (e.g., "WAF and bot-management security events delivered via the SIEM Integration API")
- Mention the delivery mechanism if distinctive (connector, agent, syslog, API, EventBridge, etc.)
- Note key CIM data models the log feeds, if relevant
- Be concrete — avoid filler phrases like "this sourcetype contains data about"

## Quality Checks

- Every `data_models` value is a `Model.Dataset` pair that exists in the latest `splunk_data_model_objects_fields_xxx.csv`
- Every `security_classification` value exists in `security_classifications_reference.md`
- `security_relevance` aligns with the sourcetype's actual security value
- Vendor identification is consistent with the sourcetype's naming convention
- Output is sorted by vendor then sourcetype
- Column count and order match the master schema (13 columns, in the order listed above)

## Deliverable

Generate `cim_sourcetype_inventory_<date-timestamp>.csv` with the columns above, sorted by vendor then sourcetype.

**Files attached with this prompt:**

- `sourcetypes_list.csv` (or whatever the input file is named)
- `security_classifications_reference.md`
- `splunk_data_model_objects_fields_<latest>.csv`
- This `sourcetype_analysis_prompt.md` (the prompt and guide for the analysis)

This prompt emphasizes thoroughness, accuracy, and proper use of reference materials. The quality checks section ensures consistent, high-quality results across different analysis runs.
