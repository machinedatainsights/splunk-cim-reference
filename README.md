# splunk-cim-reference

Reference materials for Splunk CIM (Common Information Model) normalization work: sourcetype classification, data model field definitions, and security device taxonomy. Intended as a shared resource for Splunk architects, TA developers, and security engineers working on CIM compliance.

---

## Contents

### Sourcetype Classification

| File | Description |
|------|-------------|
| `cim_sourcetype_inventory.csv` | Master reference of common Splunk sourcetypes classified by vendor, security relevance, scope, applicable CIM data models, and exclusion status. Starting point for CIM normalization projects. |
| `sourcetype_analysis_prompt.md` | Prompt and instructions for using an AI assistant to classify a new list of sourcetypes into the inventory format. |
| `sourcetypes_list.csv` | Example input file — a raw list of sourcetypes and event counts from a `tstats` search. Illustrates the expected input format for the analysis prompt. |

### CIM Data Model Reference

| File | Description |
|------|-------------|
| `splunk_data_model_objects_fields_604.csv` | Complete field reference for Splunk CIM v6.0.4 — all data models, datasets, fields, types, prescribed values, constraints, and descriptions. Source of truth for data model assignments in the sourcetype inventory. |

### Security Classification Taxonomy

| File | Description |
|------|-------------|
| `security_classifications_reference.md` | Authoritative reference for IT security device classifications used in CIM normalization. Defines 40 acronyms (EDR, NGFW, IAM, SIEM, etc.) with descriptions, vendor examples, and classification guidelines. Use this as the source of truth for `security_classification` values in the sourcetype inventory. |
| `security_classifications_reference.pdf` | PDF version of the same reference. |
| `Security-Categories-and-Acronyms.md` | Quick-reference cheat sheet of security acronyms organized by category. A condensed companion to the full reference above — useful for fast lookups. Note that the full reference is authoritative; a handful of acronyms (FW, NGFW, UTM, SWG, EPP, CTD, ESG, DT, VPN) appear there but not here. |
| `IT-Security-Device-Classifications.md` | Broader classification reference covering 15 security device categories with descriptions, vendor examples, applicable Splunk CIM data models, and common sourcetypes for each category. Useful for understanding which CIM data models a given security device type maps to. |

### CIM Data Model Parsing Tools

| File | Description |
|------|-------------|
| `parse_cim_datamodels.py` | Python script (standard library only) for parsing Splunk's CIM JSON data model files into tabular CSV format. Accepts `--models-dir` and `--output` arguments. |
| `Data_Model_JSON_Parser.ipynb` | Jupyter notebook version of the same — useful for interactive exploration and spot-checking. |

> **Note:** The parsing tools require access to Splunk's CIM app JSON files, typically found at `$SPLUNK_HOME/etc/apps/Splunk_SA_CIM/default/data/models/`.

---

## Sourcetype Inventory Format

`cim_sourcetype_inventory.csv` uses the following columns:

| Column | Description |
|--------|-------------|
| `sourcetype` | Splunk sourcetype name |
| `events` | Event count (set to 0 in the starter inventory — populate from your environment) |
| `mapped_status` | `mapped`, `unmapped`, or `excluded` |
| `scope` | `security`, `operational`, `security,operational`, `none`, or `unknown` |
| `security_classification` | Acronym(s) from `security_classifications_reference.md` (e.g., `EDR`, `NGFW`). `N/A` for non-security sourcetypes. |
| `security_relevance` | `high`, `med`, `low`, or `none` |
| `data_models` | Applicable CIM data models in `Model.Dataset` format (e.g., `Authentication.Authentication`). Up to 3, from `splunk_data_model_objects_fields_604.csv`. |
| `vendor` | Technology vendor |
| `description` | Brief description (50 characters max) |
| `exclude` | `Y` or `N` — controls whether the sourcetype is filtered from unmapped counts in CIM compliance tools |
| `exclude_reason` | Reason for exclusion if `exclude=Y` |
| `reviewed_by` | Who classified this entry |
| `reviewed_date` | Date reviewed (M/D/YYYY) |

---

## Using the Sourcetype Analysis Prompt

To classify a new batch of sourcetypes:

1. Run a `tstats` search in Splunk to get your sourcetype list with event counts:
   ```spl
   | tstats count WHERE index=* NOT index=_* BY sourcetype
   | sort - count
   | rename count as events
   ```
2. Export the results as `sourcetypes_list.csv`
3. Open an AI assistant session and attach:
   - `sourcetypes_list.csv` (your input)
   - `security_classifications_reference.md` (or `.pdf`)
   - `splunk_data_model_objects_fields_604.csv`
   - `sourcetype_analysis_prompt.md` (as the prompt)
4. The output is a `cim_sourcetype_inventory_<timestamp>.csv` ready to merge into the master inventory

---

## Updating the CIM Field Reference

The `splunk_data_model_objects_fields_604.csv` was generated from Splunk CIM v6.0.4. To regenerate for a newer CIM version:

1. Locate the CIM app JSON files on your Splunk server:
   ```
   $SPLUNK_HOME/etc/apps/Splunk_SA_CIM/default/data/models/
   ```
2. Run `parse_cim_datamodels.py` (or use the Jupyter notebook) against that directory
3. The output CSV can replace the existing file — update the filename reference in `transforms.conf` in any apps that use it

---

## Related Projects

- [CIM Assessment Toolkit (CAT)](https://splunkbase.splunk.com) — Splunk app that uses this reference data to measure CIM compliance across data models. Includes dashboard, automated report generation, and scheduled email delivery.
- [Splunk CIM Add-on](https://splunkbase.splunk.com/app/1621) — Official Splunk CIM app containing the data model definitions this reference is derived from.

---

## Contributing

Additions and corrections are welcome. If you have sourcetypes or classifications that should be in the inventory, open a PR or issue. The goal is a community-maintained reference that saves every Splunk engineer from re-doing the same classification work from scratch.

---

## License

Reference materials in this repository are released under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). Scripts are licensed under [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

**Machine Data Insights Inc.** — *"There's Gold In That Data!"*
