"""
validator.py

Validates synthetic security event records against schema.json (Technical 1).
Requires the `jsonschema` package:  pip install jsonschema

The script:
  1. Loads schema.json from the same directory as this script (no hard-coded
     absolute paths, so it works no matter where the project is checked out).
  2. Defines three sample event records: one fully valid, one missing
     confidence fields, and one missing approval fields.
  3. Validates each record and prints a clear pass/fail summary, explicitly
     calling out missing confidence or approval fields when present.

Run directly:
    python3 validator.py
"""

import json
import os
import sys

from jsonschema import Draft7Validator


# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------

def load_schema():
    """Load schema.json from the same directory as this script."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    schema_path = os.path.join(script_dir, "schema.json")
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Validation logic
# ---------------------------------------------------------------------------

def validate_record(record, validator):
    """
    Validate a single record against the schema.

    Returns a tuple: (is_valid, list_of_error_messages)

    In addition to generic schema errors, this function specifically checks
    for the two sections the assignment calls out by name -- 'confidence'
    and 'approval' -- and produces a clear, explicit message naming the
    missing field(s) when either section (or a required field inside it)
    is absent. This is on top of (not instead of) full JSON Schema
    validation, so any other structural problem is still caught too.
    """
    errors = []

    # Run full schema validation and collect every error, not just the first.
    for err in sorted(validator.iter_errors(record), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in err.path) or "(root)"
        errors.append(f"[{path}] {err.message}")

    # Targeted, human-readable checks for the two mandatory sections called
    # out explicitly in the assignment: confidence and approval.
    missing_required_sections = []
    if "confidence" not in record:
        missing_required_sections.append("confidence")
    if "approval" not in record:
        missing_required_sections.append("approval")

    if missing_required_sections:
        errors.insert(
            0,
            "Missing required top-level field(s): "
            + ", ".join(missing_required_sections),
        )
    else:
        # Sections are present but may themselves be missing required fields.
        confidence_required = ["scale", "overall_score", "overall_label", "applies_to"]
        missing_confidence_fields = [
            field for field in confidence_required
            if field not in record.get("confidence", {})
        ]
        if missing_confidence_fields:
            errors.insert(
                0,
                "Missing required confidence field(s): "
                + ", ".join(missing_confidence_fields),
            )

        approval_required = ["approval_status"]
        missing_approval_fields = [
            field for field in approval_required
            if field not in record.get("approval", {})
        ]
        if missing_approval_fields:
            errors.insert(
                0,
                "Missing required approval field(s): "
                + ", ".join(missing_approval_fields),
            )

    is_valid = len(errors) == 0
    return is_valid, errors


# ---------------------------------------------------------------------------
# Synthetic sample records
# ---------------------------------------------------------------------------

def get_sample_records():
    """
    Returns a dict of {label: record} with three synthetic sample records:
      - "valid_record": passes validation against schema.json
      - "missing_confidence": missing the 'confidence' section
      - "missing_approval": missing the 'approval' section
    """

    valid_record = {
        "event": {
            "event_id": "EVT-2026-000123",
            "timestamp": "2026-07-15T09:41:00Z",
            "source": "edr:workstation-042",
            "event_type": "malware_detection",
            "severity": "high",
            "description": "EDR flagged a known trojan signature in a downloaded executable."
        },
        "enrichment": {
            "threat_intel_matches": [
                {
                    "indicator": "185.220.101.7",
                    "indicator_type": "ip",
                    "source": "internal_threat_feed",
                    "match_type": "exact",
                    "campaign_or_actor": None
                }
            ],
            "asset_context": {
                "asset_id": "WKS-042",
                "asset_type": "workstation",
                "criticality": "medium",
                "owner": "finance_team"
            },
            "related_events": [
                {
                    "event_id": "EVT-2026-000119",
                    "relationship": "same_asset"
                }
            ]
        },
        "confidence": {
            "scale": "0-100",
            "overall_score": 82,
            "overall_label": "high",
            "applies_to": ["event.severity", "enrichment.threat_intel_matches"]
        },
        "approval": {
            "approval_status": "approved",
            "approver_id": "analyst.jsmith",
            "approval_timestamp": "2026-07-15T09:55:00Z",
            "proposed_action": "isolate host WKS-042 from network"
        },
        "audit_trail": [
            {
                "actor": "edr-system",
                "actor_type": "system",
                "action": "triaged",
                "timestamp": "2026-07-15T09:41:05Z"
            },
            {
                "actor": "enrichment-service",
                "actor_type": "system",
                "action": "enriched",
                "timestamp": "2026-07-15T09:41:10Z"
            },
            {
                "actor": "analyst.jsmith",
                "actor_type": "human",
                "action": "approved",
                "timestamp": "2026-07-15T09:55:00Z",
                "notes": "Confirmed malicious signature, approved containment."
            }
        ]
    }

    # Same as valid_record, but the entire 'confidence' section is omitted.
    missing_confidence = json.loads(json.dumps(valid_record))
    del missing_confidence["confidence"]

    # Same as valid_record, but the entire 'approval' section is omitted.
    missing_approval = json.loads(json.dumps(valid_record))
    del missing_approval["approval"]

    return {
        "valid_record": valid_record,
        "missing_confidence": missing_confidence,
        "missing_approval": missing_approval,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    schema = load_schema()
    validator = Draft7Validator(schema)

    records = get_sample_records()

    print("=" * 70)
    print("Security Event Schema Validation Summary")
    print("=" * 70)

    all_passed_as_expected = True
    # Records expected to fail validation (for the assignment's negative
    # test cases) are tracked so the summary line reflects intent, not just
    # raw pass/fail.
    expected_invalid = {"missing_confidence", "missing_approval"}

    for label, record in records.items():
        is_valid, errors = validate_record(record, validator)
        status = "PASS" if is_valid else "FAIL"
        print(f"\nRecord: {label}")
        print(f"Result: {status}")
        if errors:
            print("Errors:")
            for e in errors:
                print(f"  - {e}")

        expected_valid = label not in expected_invalid
        if is_valid != expected_valid:
            all_passed_as_expected = False

    print("\n" + "=" * 70)
    if all_passed_as_expected:
        print("Summary: all sample records behaved as expected "
              "(valid_record passed; both incomplete records were "
              "correctly rejected).")
    else:
        print("Summary: at least one sample record did NOT behave as "
              "expected. Review the errors above.")
    print("=" * 70)

    sys.exit(0 if all_passed_as_expected else 1)


if __name__ == "__main__":
    main()
