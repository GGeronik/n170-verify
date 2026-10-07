"""A bounded, escaped presentation of supplied tool output, not a credential."""
from html import escape


LABELS = {
    "FINDINGS_REPORTED": "The supplied export reports findings",
    "NO_FINDINGS_REPORTED": "The supplied export reports no findings",
    "NOT_ASSESSABLE": "The supplied export cannot be assessed",
}
ROW_LABELS = {"FINDINGS_REPORTED": "Findings reported", "NO_FINDINGS_REPORTED": "No findings reported",
              "NOT_ASSESSABLE": "Cannot assess this row"}
REASONS = {
    "UPSTREAM_FINDINGS_REPORTED": "The export identifies possible bias. Review the reported signals and indicator findings.",
    "NO_FINDINGS_IN_SUPPLIED_ROWS": "The supplied rows report no findings; untested or omitted cases remain unknown.",
    "DECLARED_RUN_NOT_COMPLETED": "The declared analysis did not complete. Obtain its failure details before relying on the export.",
    "DECLARED_STRATEGY_COUNT_MISMATCH": "The number of usable strategy rows differs from the declared scope.",
    "NO_TESTED_SIGNALS": "No tested signals are reported for a required row. Run an analysis with enough observations.",
    "EMPTY_EXPORT": "The export contains no strategy observations.",
    "CONTRADICTORY_BIAS_RESULT": "The bias flag disagrees with its counts or indicator findings. Review the original export.",
    "DUPLICATE_STRATEGY": "The same strategy and file appear more than once. Resolve duplicate evidence.",
    "UNSUPPORTED_COLUMNS": "The columns differ from the supported export format.",
    "INVALID_COUNT": "A signal count is missing or is not a supported non-negative integer.",
}


def report_for_sharing(assessment, *, include_labels=False):
    """Omit strategy/file/indicator names unless the owner explicitly includes them.

    These labels can reveal private research. The original source is never
    embedded. A digest in the assessment is a commitment, not authentication.
    """
    import copy
    report = copy.deepcopy(assessment)
    for number, row in enumerate(report.get("rows", []), 1):
        if not include_labels:
            for field in ("filename", "strategy", "biased_indicators"):
                row.pop(field, None)
        row["display_label"] = row.get("strategy", f"Strategy {number}")
    report["disclosure"] = {
        "source_text_included": False,
        "strategy_labels_included": include_labels,
        "note": "Counts and declared scope may still disclose research information. Review before sharing.",
    }
    return report


def render_html(report):
    """Produce a static local reading copy; a recipient reruns the CLI on CSV."""
    import json
    def e(value):
        return escape(str(value), quote=True)

    title = LABELS.get(report.get("status"), "The supplied export cannot be assessed")
    example = ("<p class='basis'><strong>Synthetic demonstration.</strong> These invented observations exercise the toolkit. No actual strategy or investment result is represented.</p>"
               if report.get("example_declaration") == "synthetic" else "")
    rows = []
    for row in report.get("rows", []):
        counts = [row.get(key, "Unknown") for key in
                  ("total_signals", "biased_entry_signals", "biased_exit_signals")]
        rows.append("<tr><th scope='row'>" + e(row.get("display_label", "Strategy"))
                    + "</th>" + "".join("<td>" + e(v) + "</td>" for v in counts)
                    + "<td>" + e(ROW_LABELS.get(row.get("status"), "Cannot assess this row")) + "</td></tr>")
    limits = "".join("<li>" + e(v) + "</li>" for v in report.get("limitations", []))
    reasons = "".join("<li>" + e(REASONS.get(v, v.replace("_", " ").capitalize() + ". Review the supplied format or declared scope.")) + "</li>"
                      for v in report.get("reason_codes", []))
    # JSON is escaped as text, never inserted as executable script or HTML.
    machine = e(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False))
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>N170 · Freqtrade evidence review</title><style>
*{box-sizing:border-box}body{margin:0;background:#f4f2ed;color:#192d39;font:17px/1.6 system-ui,sans-serif}
main{max-width:1050px;margin:auto;padding:44px 24px 70px}header{border-bottom:2px solid #192d39;margin-bottom:28px}
.eyebrow{font-size:13px;letter-spacing:.09em;text-transform:uppercase}h1{font-size:clamp(27px,5vw,44px);line-height:1.15;max-width:850px}
h2{font-size:23px;margin-top:34px}.basis{padding:18px 22px;background:#e5eaf0;border-left:4px solid #516e85}
.scope{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.scope p{border:1px solid #bbc6cd;padding:14px;margin:0}
table{width:100%;border-collapse:collapse;text-align:left;font-size:14px}th,td{padding:12px;border-bottom:1px solid #c2cbd0;vertical-align:top}
.table{overflow:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;background:white;padding:18px}li{margin:9px 0}
footer{margin-top:32px;color:#4d606b;font-size:14px}summary{cursor:pointer;font-weight:650}
</style></head><body><main><header><p class="eyebrow">N170 / Open evidence toolkit · Experimental</p><h1>""" + e(title) + """</h1><p>Freqtrade lookahead-analysis · supplied CSV review</p></header>
""" + example + """<div class="basis"><strong>This is a reading of supplied output.</strong> N170 did not run the strategy, authenticate this file, or establish that the research is free of bias. This is not an account-performance credential.</div>
<h2>What the evidence establishes</h2><div class="scope">
<p><strong>Export interpretation</strong><br>Known columns, counts and consistency checks</p>
<p><strong>Tool execution</strong><br>Not performed by this toolkit</p>
<p><strong>Source and time</strong><br>Unauthenticated; no independent timestamp</p>
<p><strong>Whole-run coverage</strong><br>Not established by the CSV</p></div>
<h2>Reported observations</h2><div class="table"><table><thead><tr><th>Strategy</th><th>Signals reported as tested</th><th>Biased entries</th><th>Biased exits</th><th>Row interpretation</th></tr></thead><tbody>""" + ("".join(rows) or "<tr><td colspan='5'>No assessable rows supplied.</td></tr>") + """</tbody></table></div>
<h2>Reasons and limitations</h2><ul>""" + reasons + limits + """</ul>
<h2>How someone else checks it</h2><p>Obtain an independent copy of the toolkit. Rerun <code>python -m verify_toolkit freqtrade-lookahead export.csv --context context.json</code> on the same retained source bytes and declared context. Compare its output and source digest. Omit the context option when none was supplied. Agreement establishes repeatable interpretation, not the authenticity of the export.</p>
<details><summary>Structured evidence and declared scope</summary><pre>""" + machine + """</pre></details>
<footer>This HTML is an unsigned, editable reading copy. Strategy labels are omitted by default. Review the disclosure before sharing. Free software; no accounts, uploads, telemetry or trading.</footer></main></body></html>"""
