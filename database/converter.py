import yaml
import json
from pathlib import Path

INPUT_YAML = (
    Path("bluetooth_sig")
    / "assigned_numbers"
    / "company_identifiers"
    / "company_identifiers.yaml"
)

OUTPUT_JSON = (
    Path("bluetooth_sig")
    / "assigned_numbers"
    / "company_identifiers"
    / "company_ids.json"
)

def main():
    if not INPUT_YAML.exists():
        raise FileNotFoundError(f"Missing {INPUT_YAML}")

    with open(INPUT_YAML, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if isinstance(raw, dict):
        entries = raw.get("company_identifiers", [])
    else:
        entries = raw

    company_ids = {}

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        value = entry.get("value")
        name = entry.get("name")

        if value is None or name is None:
            continue

        value_int = int(value, 16) if isinstance(value, str) else int(value)

        company_ids[str(value_int)] = {
            "hex": f"0x{value_int:04X}",
            "company": name
        }

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(company_ids, f, indent=2, sort_keys=True)

    print(f"[+] Generated {len(company_ids)} company identifiers")
    print(f"[+] Output → {OUTPUT_JSON}")

if __name__ == "__main__":
    main()
