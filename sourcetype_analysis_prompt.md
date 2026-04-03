# Sourcetype Analysis Prompt

I have a CSV file of Splunk sourcetypes with event counts that need to be analyzed and classified for CIM normalization. Please create a comprehensive analysis CSV file with the following columns:

**Output Columns:**

- sourcetype - The sourcetype name
- events - Event count from the input file
- mapped_status - Set to "unmapped" for all entries
- scope - Categorize as: security, operational, security,operational, none, or unknown
- security_classification - Use ONLY classifications from the attached 'security_classifications_reference.csv' (e.g., EDR, NGFW, IAM, etc.). Use "N/A" for non-security sourcetypes, "Unknown" if insufficient information. List up to 3 classifications if applicable.
- security_relevance - Assign: none, low, med, or high
- data_models - List up to 3 applicable CIM data models in format: data_model.dataset (e.g., Authentication.Authentication, Network_Traffic.All_Traffic). Use ONLY data models from 'splunk_data_model_objects_fields_604.csv'
- vendor - Identify the technology vendor(s) or leave blank if unknown/not applicable
- description - Brief description (50 characters max)
- exclude - Set to "N" for all entries
- exclude_reason - Leave blank
- reviewed_by - Set to "AI Analysis"
- reviewed_date - Use today's date in M/D/YYYY format

**CRITICAL REQUIREMENTS:**

- Work through ALL sourcetypes systematically - Do not skip any entries
- Take your time with each sourcetype - Carefully analyze what each sourcetype represents before assigning classifications

**Data Model Mapping Accuracy:**
- Reference the 'splunk_data_model_objects_fields_604.csv' file for ALL data model assignments
- Do NOT make up or assume data models - only use what exists in the reference file
- Prioritize data models from most specific to least specific (up to 3 maximum)
- Consider what fields the sourcetype likely contains and which data models those fields map to
- For example: authentication logs → Authentication.Authentication; firewall traffic → Network_Traffic.All_Traffic, Intrusion_Detection.IDS_Attacks (if threat data present)

**Security Classification Accuracy:**
- Reference the 'security_classifications_reference.csv' for ALL classifications
- Think about the primary security function of the technology
- For multi-function devices (e.g., NGFW with IPS), list multiple classifications

**Security Relevance Guidelines:**
- High: Direct threat detection, authentication/authorization, vulnerability data, security alerts
- Med: Audit logs, configuration changes, access logs, compliance data
- Low: Inventory, informational logs, package management
- None: Pure performance metrics, statistics with no security value

**Scope Guidelines:**
- security: Primary purpose is security monitoring/detection
- operational: Primary purpose is system/application performance, availability, inventory
- security,operational: Serves both purposes equally (rare - be selective)
- unknown: Insufficient information to determine

**Quality Checks:**
- Verify each sourcetype's data_models exist in the reference CSV
- Ensure security_classification matches entries in the reference CSV
- Double-check that security_relevance aligns with the sourcetype's actual security value
- Confirm vendor identification is accurate based on sourcetype naming conventions

Please analyze the attached 'unmapped.csv' file and generate the complete analysis. Your output is a ‘cim_sourcetype_inventory_<date-timestamp>.csv file.

Files to be attach with this prompt:

sourcetypes-list_3-25-2026.csv (or whatever the input file is named)
security_classifications_reference.csv
splunk_data_model_objects_fields_604.csv

And this sourcetype-analysis-prompt.md to serve as the prompt and guide for the analysis.

This prompt emphasizes thoroughness, accuracy, and proper use of reference materials. The quality checks section should help ensure consistent, high-quality results across different analysis runs.
