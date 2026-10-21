"""Console, JSON, CSV and HTML output for scan results."""

from __future__ import annotations

import csv
import html
import json
from collections import defaultdict
from pathlib import Path

from .models import SEVERITY_ORDER, Finding
from .scanner import ScanResult

_TAG = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}


def console_report(result: ScanResult) -> str:
    passed, failed, errors = (len(result.by_status(s)) for s in ("PASS", "FAIL", "ERROR"))
    lines = [
        f"Account {result.account_id} | regions: {', '.join(result.regions)}",
        f"Security score: {result.score}/100   PASS {passed}   FAIL {failed}   ERROR {errors}",
        "",
    ]
    if result.failed:
        lines.append("Failed checks (most severe first):")
        for f in result.failed:
            lines.append(f"  [{_TAG[f.severity]}] {f.check_id:<8} {f.region:<10} {f.resource:<40} {f.details}")
    else:
        lines.append("All checks passed.")
    for f in result.by_status("ERROR"):
        lines.append(f"  [ERR ] {f.check_id:<8} {f.region:<10} {f.details}")
    return "\n".join(lines)


def write_json(result: ScanResult, path: Path) -> None:
    payload = {
        "account_id": result.account_id,
        "regions": result.regions,
        "scanned_at": result.started_at.isoformat(timespec="seconds"),
        "score": result.score,
        "summary": {s: len(result.by_status(s)) for s in ("PASS", "FAIL", "ERROR")},
        "failed_by_severity": result.failed_by_severity(),
        "findings": [f.to_dict() for f in result.findings],
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def write_csv(result: ScanResult, path: Path) -> None:
    fields = ["check_id", "title", "service", "severity", "status", "region", "resource", "details", "cis"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for f in result.findings:
            writer.writerow(f.to_dict())


_CSS = """
:root{--bg:#f4f6f8;--card:#fff;--ink:#14202e;--muted:#5b6878;--line:#dde3ea;
--crit:#b42318;--high:#c4320a;--med:#b54708;--low:#475467;--pass:#067647}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:32px 16px}
main{max-width:1100px;margin:0 auto}h1{margin:0 0 4px;font-size:26px}
.sub{color:var(--muted);margin:0 0 24px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:28px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.tile b{display:block;font-size:28px;font-variant-numeric:tabular-nums}.tile span{color:var(--muted);font-size:13px}
h2{font-size:18px;margin:28px 0 10px}
.check{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:12px;overflow:hidden}
.check header{display:flex;gap:10px;align-items:center;padding:12px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.check header h3{margin:0;font-size:15px;flex:1;min-width:220px}
.pill{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:#fff;padding:2px 8px;border-radius:99px}
.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med)}.low{background:var(--low)}
.meta{font-size:12px;color:var(--muted)}
.wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed}
col.r{width:42%}col.g{width:14%}td{overflow-wrap:anywhere}th,td{text-align:left;padding:8px 16px;border-top:1px solid var(--line);vertical-align:top}
th{background:#f9fafb;font-weight:600;color:var(--muted);border-top:0}
code{font-family:ui-monospace,Menlo,monospace;font-size:12px}
.fix{padding:10px 16px;font-size:13px;background:#f9fafb;border-top:1px solid var(--line)}
.ok{color:var(--pass);font-weight:600}
"""


def write_html(result: ScanResult, path: Path) -> None:
    esc = html.escape
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in result.failed:
        grouped[f.check_id].append(f)
    passed_checks = sorted({f.check_id for f in result.by_status("PASS")} - set(grouped))
    sev = result.failed_by_severity()

    tiles = [(f"{result.score}/100", "Security score"),
             (str(len(result.by_status("FAIL"))), "Failed resources"),
             (str(sev.get("critical", 0) + sev.get("high", 0)), "Critical + high"),
             (str(len(result.by_status("PASS"))), "Passed resources")]

    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>AWS Security Report {esc(result.account_id)}</title><style>{_CSS}</style></head><body><main>",
        "<h1>AWS Security Posture Report</h1>",
        f"<p class='sub'>Account {esc(result.account_id)} &middot; Regions: {esc(', '.join(result.regions))} "
        f"&middot; Scanned {result.started_at:%Y-%m-%d %H:%M} UTC</p>",
        "<div class='tiles'>",
        *[f"<div class='tile'><b>{esc(v)}</b><span>{esc(label)}</span></div>" for v, label in tiles],
        "</div>",
        "<h2>Failed checks</h2>",
    ]
    if not grouped:
        parts.append("<p class='ok'>No failed checks.</p>")
    ordered = sorted(grouped.items(), key=lambda kv: (-SEVERITY_ORDER[kv[1][0].severity], kv[0]))
    for check_id, items in ordered:
        first = items[0]
        cis = f"CIS {esc(first.cis)} &middot; " if first.cis != "-" else ""
        rows = "".join(f"<tr><td><code>{esc(f.resource)}</code></td><td>{esc(f.region)}</td>"
                       f"<td>{esc(f.details)}</td></tr>" for f in items)
        parts.append(
            f"<section class='check'><header><span class='pill {first.severity}'>{first.severity}</span>"
            f"<h3>{esc(check_id)} &middot; {esc(first.title)}</h3>"
            f"<span class='meta'>{cis}{esc(first.service)}</span></header>"
            f"<div class='wrap'><table><colgroup><col class='r'><col class='g'><col></colgroup>"
            f"<tr><th>Resource</th><th>Region</th><th>Detail</th></tr>{rows}</table></div>"
            f"<div class='fix'><b>Fix:</b> <code>{esc(first.remediation)}</code></div></section>"
        )
    if passed_checks:
        parts.append("<h2>Passed checks</h2><p>" + ", ".join(f"<code>{esc(c)}</code>" for c in passed_checks)
                     + "</p>")
    errors = result.by_status("ERROR")
    if errors:
        parts.append("<h2>Checks that could not run</h2><div class='check wrap'><table>"
                     "<tr><th>Check</th><th>Region</th><th>Error</th></tr>")
        parts += [f"<tr><td>{esc(f.check_id)}</td><td>{esc(f.region)}</td><td>{esc(f.details)}</td></tr>"
                  for f in errors]
        parts.append("</table></div>")
    parts.append("</main></body></html>")
    path.write_text("\n".join(parts), encoding="utf-8")
