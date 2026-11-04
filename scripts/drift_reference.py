"""Write the drift check's reference (src/phish_triage/service/drift_reference.json); `make drift-reference`.

The bundle named in infra/bundle-version scores, one email at a time as the service does, the legitimate mail it never
trained on: my test inbox's held-out senders and PrivacyMail's held-out websites. Only the bin counts of the three
distributions the check compares are written (`service/drift.py`), with the bundle's version, so the file is an
aggregate and can be committed. Rerun it whenever infra/bundle-version changes; the gate checks that it matches.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path


def main() -> int:
    from phish_triage.data import inbox, privacymail
    from phish_triage.service.bundle import BUNDLE_ROOT
    from phish_triage.service.drift import REFERENCE, distributions
    from phish_triage.service.scanner import Scanner

    version = Path("infra/bundle-version").read_text().strip()
    _, inbox_slices = inbox.load_split()
    _, newsletter_slices = privacymail.load_split()
    ids = inbox_slices["inbox_test"] + newsletter_slices["privacymail_test"]
    records = inbox.read_split_records(set(ids))
    scanner = Scanner(BUNDLE_ROOT / version, threads=4)
    verdicts = []
    for i in ids:
        result = scanner.scan_record(records[i])
        verdicts.append({"score": result.score, "stage": result.stage, "sender": result.sender})
    reference = {
        "bundle": version,
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "emails": len(verdicts),
        "from": "legitimate mail the bundle never trained on: the inbox's and PrivacyMail's held-out test slices",
        "counts": distributions(verdicts),
    }
    REFERENCE.write_text(json.dumps(reference, indent=1) + "\n")
    print(f"{REFERENCE}: {len(verdicts)} emails, bundle {version}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
