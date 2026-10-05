"""Generate the public structural schema from the existing Python contracts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from decision_mesh.contracts import event_schema


def schema_bytes() -> bytes:
    schema = event_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "urn:decisionmesh:event-envelope:v1"
    return (json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = ROOT / "npm/decisionmesh/schemas/event.schema.json"
    expected = schema_bytes()
    if args.check:
        if not target.is_file() or target.read_bytes() != expected:
            print("Bundled schema differs from current contracts.", file=sys.stderr)
            return 1
        print("Bundled schema matches current contracts.")
        return 0
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(expected)
    print("Exported public structural event schema.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
