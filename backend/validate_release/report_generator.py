import json
from pathlib import Path
from datetime import datetime

def generate_report(status, patch_id, test_output):

    report = {
        "patch_id": patch_id,
        "status": status,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "test_summary": test_output
    }

    output_file = Path(__file__).parent / "validation_report.json"

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    return report