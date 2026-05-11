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
    python parse_cim_datamodels.py --models-dir ./models
    python parse_cim_datamodels.py --cim-version 8.5.0
    python parse_cim_datamodels.py --output ./splunk_data_model_objects_fields_850.csv --force

Instructions:
    1. Download and unzip the latest Splunk Common Information Model app from Splunkbase:
       https://splunkbase.splunk.com/app/1621
    2. Copy the data model .json files (Alerts.json, Authentication.json, etc.) from:
       <unzipped>/Splunk_SA_CIM/default/data/models/
       into a local folder (default: ./models). Optionally include the app's
       default/app.conf alongside or above the models folder to enable
       automatic CIM version detection.
    3. Run this script. If a Splunk_SA_CIM app.conf is reachable from the
       models directory (typically at ../../app.conf), the CIM version is
       auto-detected and the default output filename becomes
       splunk_data_model_objects_fields_<version_no_dots>.csv (e.g., _850.csv).
       Otherwise the default falls back to the unversioned
       splunk_data_model_objects_fields.csv.
    4. Pass --cim-version X.Y.Z to override or supply the version label
       manually, and --force to overwrite an existing output file.
"""

import os
import json
import csv
import argparse


def detect_cim_version(models_dir):
    """Return the Splunk_SA_CIM app version from a nearby app.conf, or None.

    Looks for app.conf in the models directory itself and in the standard
    Splunk app layout (default/data/models/ -> default/app.conf, two levels up).
    """
    candidates = [
        os.path.join(models_dir, "app.conf"),
        os.path.normpath(os.path.join(models_dir, "..", "..", "app.conf")),
        os.path.normpath(os.path.join(models_dir, "..", "..", "..", "default", "app.conf")),
    ]
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, "r", encoding="utf-8-sig", errors="replace") as f:
                section = None
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("[") and line.endswith("]"):
                        section = line[1:-1].strip().lower()
                        continue
                    if section in ("launcher", "install") and "=" in line:
                        key, _, value = line.partition("=")
                        if key.strip().lower() == "version":
                            version = value.strip()
                            if version:
                                return version
        except OSError:
            continue
    return None


def default_output_path(version):
    """Build the default output CSV path, embedding a compact version if available."""
    if version:
        compact = "".join(c for c in version if c.isdigit())
        if compact:
            return f"./splunk_data_model_objects_fields_{compact}.csv"
    return "./splunk_data_model_objects_fields.csv"


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
        default=None,
        help=(
            "Output CSV filename. If omitted, defaults to "
            "./splunk_data_model_objects_fields_<version>.csv when a CIM version "
            "is auto-detected (or supplied via --cim-version); otherwise "
            "./splunk_data_model_objects_fields.csv."
        ),
    )
    parser.add_argument(
        "--cim-version",
        default=None,
        help="Override the CIM version label used in the default output filename (e.g., 8.5.0).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output CSV if it already exists.",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.models_dir):
        print(f"Error: models directory '{args.models_dir}' not found.")
        raise SystemExit(1)

    output_path = args.output
    if not output_path:
        version = args.cim_version or detect_cim_version(args.models_dir)
        output_path = default_output_path(version)
        if version:
            print(f"Using CIM version '{version}' -> output: {output_path}")
        else:
            print(f"CIM version not detected; output: {output_path}")
            print("  (pass --cim-version X.Y.Z to embed a version in the default filename)")

    if os.path.exists(output_path) and not args.force:
        print(
            f"Error: output file '{output_path}' already exists. "
            "Pass --force to overwrite, or choose a different --output path."
        )
        raise SystemExit(2)

    parse_models(args.models_dir, output_path)


if __name__ == "__main__":
    main()
