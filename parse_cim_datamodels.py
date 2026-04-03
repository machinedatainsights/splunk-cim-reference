# parse_cim_datamodels.py
# Machine Data Insights Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Parses Splunk CIM data model JSON files into a flat CSV reference file.

Usage:
    python parse_cim_datamodels.py
    python parse_cim_datamodels.py --models-dir ./models --output splunk_data_model_objects_fields_604.csv

Instructions:
    1. Download and unzip the latest Splunk Common Information Model app from Splunkbase:
       https://splunkbase.splunk.com/app/1621
    2. Copy the data model .json files (Alerts.json, Authentication.json, etc.) from:
       <unzipped>/Splunk_SA_CIM/default/data/models/
       into a local folder (default: ./models)
    3. Run this script. The output CSV will be written to the current directory.
    4. Update --output to reflect the CIM version (e.g., splunk_data_model_objects_fields_605.csv)
       when parsing a newer CIM release.
"""

import os
import json
import csv
import argparse


def parse_models(models_dir, output_path):
    prefix = "BaseEvent."
    prefix2 = "BaseSearch."

    records = []

    json_files = [f for f in os.listdir(models_dir) if f.endswith(".json")]
    if not json_files:
        print(f"No JSON files found in '{models_dir}'. Check the path and try again.")
        return

    print(f"Found {len(json_files)} JSON file(s) in '{models_dir}'")

    for filename in sorted(json_files):
        file_path = os.path.join(models_dir, filename)
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        model = data.get("modelName", os.path.splitext(filename)[0])
        print(f"  Parsing: {model}")

        for obj in data.get("objects", []):
            object_name = obj.get("objectName", "")
            parent_name = obj.get("parentName", "")
            base_search = obj.get("baseSearch", "")
            owner = f"{parent_name}.{object_name}" if parent_name else object_name
            dataset = (
                owner[len(prefix):]  if owner.startswith(prefix)  else
                owner[len(prefix2):] if owner.startswith(prefix2) else
                owner
            )
            constraints = "; ".join(
                c.get("search", "")
                for c in obj.get("constraints", [])
                if isinstance(c, dict) and "search" in c
            )

            # Extracted fields
            for field in obj.get("fields", []):
                comment = field.get("comment", {}) or {}
                records.append({
                    "model": model,
                    "object_name": object_name,
                    "parentName": parent_name,
                    "owner": owner,
                    "dataset": dataset,
                    "field_name": field.get("fieldName", ""),
                    "display_name": field.get("displayName", ""),
                    "type": field.get("type", ""),
                    "required": field.get("required", False),
                    "recommended": comment.get("recommended", False),
                    "extracted_type": "extracted",
                    "calculation_type": "",
                    "expression": "",
                    "base_search": base_search,
                    "constraints": constraints,
                    "prescribed_values": ", ".join(comment.get("expected_values", [])) if comment.get("expected_values") else "",
                    "description": comment.get("description", ""),
                })

            # Calculated fields
            for calc in obj.get("calculations", []):
                calc_type = calc.get("calculationType", "")
                expression = calc.get("expression", "")
                for field in calc.get("outputFields", []):
                    comment = field.get("comment", {}) or {}
                    records.append({
                        "model": model,
                        "object_name": object_name,
                        "parentName": parent_name,
                        "owner": owner,
                        "dataset": dataset,
                        "field_name": field.get("fieldName", ""),
                        "display_name": field.get("displayName", ""),
                        "type": field.get("type", ""),
                        "required": field.get("required", False),
                        "recommended": comment.get("recommended", False),
                        "extracted_type": "calculated",
                        "calculation_type": calc_type,
                        "expression": expression,
                        "base_search": base_search,
                        "constraints": constraints,
                        "prescribed_values": ", ".join(comment.get("expected_values", [])) if comment.get("expected_values") else "",
                        "description": comment.get("description", ""),
                    })

    if not records:
        print("No records extracted. Verify the JSON files are valid CIM data model files.")
        return

    fieldnames = [
        "model", "object_name", "parentName", "owner", "dataset",
        "field_name", "display_name", "type", "required", "recommended",
        "extracted_type", "calculation_type", "expression", "base_search",
        "constraints", "prescribed_values", "description",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    print(f"\nDone. {len(records)} rows written to '{output_path}'")


def main():
    parser = argparse.ArgumentParser(
        description="Parse Splunk CIM data model JSON files into a flat CSV reference file."
    )
    parser.add_argument(
        "--models-dir",
        default="./models",
        help="Directory containing CIM data model .json files (default: ./models)",
    )
    parser.add_argument(
        "--output",
        default="./splunk_data_model_objects_fields_604.csv",
        help="Output CSV filename (default: ./splunk_data_model_objects_fields_604.csv)",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.models_dir):
        print(f"Error: models directory '{args.models_dir}' not found.")
        raise SystemExit(1)

    parse_models(args.models_dir, args.output)


if __name__ == "__main__":
    main()
