"""Produce a markdown report draft from findings.

Format: Summary / Severity suggestion / Steps to Reproduce / PoC / Impact.
The draft is a starting point — the hunter reviews the Impact section and
the program format.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Iterable

# legacy Turkish statuses → English (new findings are stored in English already)
STATUS_TR = {"DOĞRULANDI": "CONFIRMED", "ŞÜPHELİ": "SUSPECT", "ÇÜRÜTÜLDÜ": "REFUTED",
             "CONFIRMED": "CONFIRMED", "SUSPECT": "SUSPECT", "REFUTED": "REFUTED"}


def _request_block(req: sqlite3.Row) -> str:
    lines = [f"{req['method']} {req['url']} HTTP/1.1"]
    try:
        headers = json.loads(req["req_headers"])
        lines += [f"{k}: {v}" for k, v in headers.items()]
    except (json.JSONDecodeError, TypeError):
        pass
    if req["req_body"]:
        lines += ["", req["req_body"][:2000]]
    return "\n".join(lines)


def render_markdown(findings: Iterable[sqlite3.Row], db) -> str:
    findings = list(findings)
    out = [
        "# AVCI — Bug Bounty Report Draft",
        "",
        f"_Generated: {time.strftime('%Y-%m-%d %H:%M')} — "
        f"{len(findings)} findings. Tool: AVCI (authorized-scope testing)._",
        "",
    ]
    for i, f in enumerate(findings, 1):
        req = db.get_request(f["request_id"]) if f["request_id"] else None
        run = db.get_test_run(f["run_id"]) if f["run_id"] else None

        out += [
            "---",
            "",
            f"## {i}. {f['title']}",
            "",
            f"- **Status:** {f['status']}",
            f"- **Suggested severity:** {f['severity']}",
            f"- **Surface:** `{f['host']}{f['path_template']}`",
            "",
            "### Summary",
            "",
            f"{f['notes'] or '_(fill in)_'}",
            "",
            "### Steps to Reproduce",
            "",
        ]
        if req is not None:
            out += [
                f"1. Send the following request to the target (including session headers):",
                "",
                "```http",
                _request_block(req),
                "```",
                "",
            ]
            step = 2
            if run is not None:
                out += [
                    f"{step}. Run the test variation: `{run['run_dir']}/test.py` "
                    f"(toplam {run['total_req']} istek)",
                    f"{step + 1}. Compare the results against baseline (status / body length / JSON fields)",
                    "",
                ]
        else:
            out += ["1. _(request record not found — see the finding notes)_", ""]

        out += ["### PoC", ""]
        if run is not None and run["verdict"]:
            out += [f"**Test yorumu (jackboot):** {run['verdict']}", ""]
        if run is not None:
            out += [
                f"Run record: `{run['run_dir']}` (`results.jsonl` + `test.py`)",
                "",
            ]
        if req is not None and req["notes"]:
            out += ["**Analyst notes:**", "", req["notes"], ""]

        out += [
            "### Impact",
            "",
            "_(write the impact analysis here — data access, transaction replay, price manipulation, etc.)_",
            "",
        ]
    return "\n".join(out)
