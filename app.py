"""Drift — configuration comparison (Streamlit).

Run:  streamlit run app.py
Files: core.py (parsing + logic) · data.py (sample data) · explain.py (AI) · ui.py (HTML/CSS)

Flow: the app starts empty. Upload a CURRENT file (JSON or sshd_config). A BASELINE file is optional:
with one, the two files are compared; without one, the current file is checked against the
built-in standard baseline.
"""
import json
from datetime import datetime
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

from core import (RISK_ORDER, STANDARD_BASELINE, TYPE_LABEL, ConfigError, analyze, build_run, f_actual,
                  f_expected, label, report_csv, report_data, totals)
from data import get_mock_servers
from security_evaluator import parse_security_file, evaluate_security_baseline
from explain import explain
from ui import (BRAND, CSS, FOOTER, baseline_table, chip, empty, empty_clean, empty_state, esc, features,
                finding_chips, fmt_date, hero, raw_json, ready_line, result_head, rich, ring,
                risk_badge, session_pill, status_badge, step_head, time_ago, trend, type_badge, verdict)

st.set_page_config(page_title="Drift · Configuration comparison", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="collapsed")
st.markdown(f"<style>{CSS}</style>", unsafe_allow_html=True)

ss = st.session_state
DEC_FILE = Path(__file__).with_name("decisions.json")
NAV = [
    ("compare", "Compare"),
    ("security_scan", "Security Scan"),
    ("findings", "Findings"),
    ("remediation", "Remediation"),
    ("reports", "Reports"),
]
PAGES = dict(NAV)


def H(html: str):
    """Render an HTML snippet."""
    if not html.startswith(("<div", "<svg", "<section", "<table")):
        html = f"<div>{html}</div>"
    st.markdown(html, unsafe_allow_html=True)


# ================================================================= state
def load_decisions() -> dict:
    try:
        return json.loads(DEC_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_decisions():
    try:
        DEC_FILE.write_text(json.dumps(ss.decisions, indent=2), encoding="utf-8")
    except Exception:
        pass  # read-only folder: keep decisions in memory only


if "ready" not in ss:
    ss.ready = True
    qp = st.query_params.get("page", "compare")
    ss.page = qp if qp in PAGES else "compare"
    ss.run = None            # nothing loaded: the app starts empty
    ss.history = []
    ss.decisions = load_decisions()
    ss.review_id = None
    ss.error = ""
    ss.security_scan = None
    ss.security_scan_error = ""


def go(page: str):
    ss.page = page
    st.query_params["page"] = page


def open_review(fid: str):
    ss.review_id = fid


def decide(fid: str, status: str):
    if status == "Pending":
        ss.decisions.pop(fid, None)
        msg = "Decision reopened"
    else:
        ss.decisions[fid] = {"status": status, "by": "You", "at": datetime.now().isoformat(timespec="seconds"),
                             "note": ss.get(f"note_{fid}", "")}
        msg = f"Fix {status.lower()} (recorded only; no server was changed)"
    save_decisions()
    ss.flash = msg
    ss.review_id = fid          # reopen the panel so the new state is visible
    st.rerun()


def dstatus(fid: str) -> str:
    return ss.decisions.get(fid, {}).get("status", "Pending")


def run_comparison(cur_name, cur_bytes, base_name=None, base_bytes=None):
    try:
        run = build_run(cur_name, cur_bytes, base_name, base_bytes)
    except ConfigError as e:
        ss.error = str(e)
        return

    # Keep the standard security review separate from custom findings and scoring.
    run["standard_security_review"] = None
    run["standard_security_review_error"] = ""

    # When both uploaded files are SSH configurations, automatically assess the
    # current file against the standard SSH rules as a separate security review.
    if (
        run["mode"] == "custom"
        and run["kind"] == "ssh"
        and run["base_kind"] == "ssh"
    ):
        try:
            parsed_current = parse_security_file(cur_name, cur_bytes)
            if parsed_current["platform"] != "ssh":
                raise ValueError(
                    "The current file could not be identified as an SSH configuration."
                )
            run["standard_security_review"] = evaluate_security_baseline(
                [parsed_current],
                platforms_only={"ssh"},
            )
        except Exception as exc:
            # A standard-review error must not block the custom comparison.
            run["standard_security_review_error"] = str(exc)

    ss.run, ss.error = run, ""
    a = analyze(run)
    ss.history.append({"time": run["last_scan"], "name": run["name"], "against": run["base_label"],
                       "drifts": len(a["findings"]), "high": sum(f["risk"] == "High" for f in a["findings"]),
                       "score": a["score"]})
    ss.flash = "Comparison complete"
    go("findings")


def do_compare():
    uploads = ss.get("up_curs") or []

    # Backward compatibility until the Compare uploader is changed.
    if not uploads:
        single_upload = ss.get("up_cur")
        if single_upload:
            uploads = [single_upload]

    base = ss.get("up_base")

    if not uploads:
        ss.error = "Add at least one current configuration file first."
        return

    # Custom baseline: preserve the existing comparison workflow.
    if base:
        if len(uploads) != 1:
            ss.error = (
                "When using a custom baseline, upload exactly one current "
                "configuration file."
            )
            return

        current = uploads[0]
        run_comparison(
            current.name,
            current.getvalue(),
            base.name,
            base.getvalue(),
        )
        return

    # No custom baseline: evaluate all uploaded files against all 106 rules.
    try:
        parsed_files = [
            parse_security_file(uploaded.name, uploaded.getvalue())
            for uploaded in uploads
        ]

        assessment = evaluate_security_baseline(
            parsed_files,
            include_unavailable_platforms=True,
        )

        run = {
            "id": datetime.now().strftime("%Y%m%d%H%M%S"),
            "name": ", ".join(uploaded.name for uploaded in uploads),
            "kind": "Security Assessment",
            "base_label": "Built-in 106-rule security baseline",
            "last_scan": datetime.now(),
            "mode": "security",
            "baseline": {},
            "current": {},
            "security_assessment": assessment,
            "uploaded_files": [uploaded.name for uploaded in uploads],
        }

        ss.run = run
        ss.error = ""
        ss.flash = "106-rule security assessment completed"
        go("findings")

    except Exception as exc:
        ss.error = f"Security assessment could not be completed: {exc}"


def do_sample():
    try:
        sample_path = Path(__file__).with_name("sample_sshd_config")
        sample_bytes = sample_path.read_bytes()

        parsed = parse_security_file(
            sample_path.name,
            sample_bytes,
        )

        assessment = evaluate_security_baseline(
            [parsed],
            include_unavailable_platforms=True,
        )

        run = {
            "id": datetime.now().strftime("%Y%m%d%H%M%S"),
            "name": sample_path.name,
            "kind": "Security Assessment",
            "base_label": "Built-in 106-rule security baseline",
            "last_scan": datetime.now(),
            "mode": "security",
            "baseline": {},
            "current": {},
            "security_assessment": assessment,
            "uploaded_files": [sample_path.name],
        }

        ss.run = run
        ss.error = ""
        ss.flash = "Sample security assessment completed"
        go("findings")

    except Exception as exc:
        ss.error = f"Sample assessment could not be completed: {exc}"


def do_security_scan():
    uploads = ss.get("security_files") or []
    if not uploads:
        ss.security_scan_error = "Upload at least one configuration file before starting the scan."
        return

    parsed_files = []
    try:
        for uploaded in uploads:
            parsed_files.append(parse_security_file(uploaded.name, uploaded.getvalue()))

        result = evaluate_security_baseline(parsed_files)
        ss.security_scan = result
        ss.security_scan_error = ""
        ss.flash = "Security scan completed"
        go("security_scan")
    except Exception as exc:
        ss.security_scan_error = str(exc)


# ================================================================= data
A = [analyze(ss.run)] if ss.run else []
T = totals(A)
PENDING = sum(1 for f in T["all"] if dstatus(f["id"]) == "Pending")
BY_ID = {f["id"]: (f, s) for s in A for f in s["findings"]}

if ss.get("flash"):
    st.toast(ss.pop("flash"))


# ================================================================= helpers
def table(prefix: str, widths: list, headers: list, rows: list):
    """A styled table made of columns. Each cell is an HTML string or a function that draws widgets."""
    with st.container(key=f"tbl_{prefix}"):
        with st.container(key=f"thead_{prefix}"):
            for c, h in zip(st.columns(widths), headers):
                c.markdown(f'<div class="th">{h}</div>', unsafe_allow_html=True)
        for i, row in enumerate(rows):
            with st.container(key=f"trow_{prefix}_{i}"):
                for c, cell in zip(st.columns(widths, vertical_alignment="center"), row):
                    with c:
                        if callable(cell):
                            cell()
                        else:
                            H(cell)


def review_btn(fid: str, ctx: str):
    def _draw():
        st.button("Review", key=f"rev_{ctx}_{fid}", on_click=open_review, args=(fid,))
    return _draw


def need_run(title: str, msg: str) -> bool:
    """Empty state for pages that need a comparison. Returns True when there is nothing to show."""
    if ss.run:
        return False
    H(empty_state(title, msg))
    st.write("")
    _, mid, _ = st.columns([2, 1.2, 2])
    mid.button("Start a comparison", key=f"start_{ss.page}", type="primary", on_click=go, args=("compare",))
    return True


# ================================================================= top navigation
active = ss.page

dyn = (
    f".st-key-nav_{active} button {{"
    "background:var(--raised)!important;"
    "color:var(--accent-cyan)!important;"
    "font-weight:600!important;"
    "border-color:rgba(70,237,224,0.32)!important;"
    "}"
)

if PENDING:
    dyn += (
        f'.st-key-nav_remediation button::after {{'
        f'content:"{PENDING}";'
        'margin-left:7px;'
        'background:var(--accent);'
        'color:#061410;'
        'border-radius:999px;'
        'font-size:.66rem;'
        'font-weight:700;'
        'padding:1px 6px;'
        '}'
    )

st.markdown(f"<style>{dyn}</style>", unsafe_allow_html=True)

with st.container(key="topnav"):
    nav_cols = st.columns([1.8, 1.1, 1.35, 1.1, 1.35, 1.05, 2.4], vertical_alignment="center")
    nav_cols[0].markdown(BRAND, unsafe_allow_html=True)
    for col, (key, text) in zip(nav_cols[1:6], NAV):
        with col:
            st.button(
                text,
                key=f"nav_{key}",
                on_click=go,
                args=(key,),
                use_container_width=True,
            )
    nav_cols[6].markdown(session_pill(ss.run), unsafe_allow_html=True)


# ================================================================= pages
def page_compare():
    H(hero())

    left, right = st.columns(2, gap="large")

    with left:
        with st.container(key="card_cur"):
            H(step_head(
                "1",
                "Current configuration",
                "Required",
                "req",
                "Upload one or more configuration files from the server you want to assess."
            ))

            st.file_uploader(
                "Current configuration",
                accept_multiple_files=True,
                key="up_curs",
                label_visibility="collapsed",
                help="You can upload SSH, Ubuntu and NGINX configuration files together."
            )

    with right:
        with st.container(key="card_base"):
            H(step_head(
                "2",
                "Baseline",
                "Optional",
                "opt",
                "Upload your own baseline for a traditional comparison. Leave empty to use all 106 built-in security rules."
            ))

            st.file_uploader(
                "Baseline",
                key="up_base",
                label_visibility="collapsed"
            )

    curs = ss.get("up_curs") or []
    base = ss.get("up_base")

    if curs:
        filenames = ", ".join(
            f"<b>{esc(upload.name)}</b>" for upload in curs
        )

        if base:
            if len(curs) == 1:
                H(ready_line(
                    f"{filenames} will be compared with your custom baseline "
                    f"<b>{esc(base.name)}</b>",
                    True
                ))
            else:
                st.warning(
                    "Custom baseline comparison requires exactly one current "
                    "configuration file. Remove the extra files to continue."
                )
        else:
            H(ready_line(
                f"{filenames} will be assessed against all "
                "<b>106 built-in security rules</b>",
                True
            ))
    else:
        H(ready_line(
            "Add at least one current configuration to begin",
            False
        ))

    if ss.error:
        _, mid, _ = st.columns([1, 3, 1])
        mid.error(ss.error)

    _, b1, b2, _ = st.columns(
        [2, 1.3, 1.3, 2],
        vertical_alignment="center"
    )

    b1.button(
        "Compare",
        key="do_compare",
        type="primary",
        disabled=not curs or (bool(base) and len(curs) != 1),
        on_click=do_compare,
        use_container_width=True
    )

    b2.button(
        "Try sample data",
        key="do_sample",
        type="tertiary",
        on_click=do_sample,
        use_container_width=True
    )

    st.write("")

    with st.expander("What is the standard baseline?"):
        st.caption(
            "The built-in baseline contains 106 security rules: "
            "53 Ubuntu 22.04, 49 SSH and 4 NGINX rules. "
            "Rules without available evidence are shown as Not Checkable "
            "or Manual Review rather than being marked as failures."
        )
        H(baseline_table())

    H(features())


def page_security_scan():
    H('<div class="res-head"><div class="eyebrow"><i></i>BUILT-IN SECURITY ASSESSMENT</div>'
      '<h1 style="font-family:var(--display)">Security Scan</h1>'
      '<p class="sub muted" style="margin-top:8px">Upload configuration files from the same server. '
      'The scanner evaluates them against the built-in 106-rule security baseline.</p></div>')

    st.info(
        "Supported inputs include Ubuntu sysctl configuration, /proc/cpuinfo, "
        "sshd_config, and NGINX .conf files. Upload multiple files from one server "
        "in the same scan. This tool analyses uploaded content only; it does not connect "
        "to or modify your server."
    )
    st.file_uploader(
        "Configuration files",
        accept_multiple_files=True,
        key="security_files",
        help="Select multiple configuration files belonging to the same server.",
    )
    uploads = ss.get("security_files") or []
    if uploads:
        st.caption("Selected files: " + " · ".join(upload.name for upload in uploads))

    _, scan_button, _ = st.columns([2, 1.5, 2])
    scan_button.button(
        "Run Security Scan",
        key="run_security_scan",
        type="primary",
        disabled=not uploads,
        on_click=do_security_scan,
        use_container_width=True,
    )

    if ss.security_scan_error:
        st.error(ss.security_scan_error)

    result = ss.security_scan
    if not result:
        return

    results = result.get("results", [])
    counts = result.get("counts", {})
    platforms = result.get("platforms_checked", [])

    st.write("")
    st.markdown("#### Scan summary")
    metric_cols = st.columns(5)
    for col, status in zip(
        metric_cols,
        ["Pass", "Fail", "Not Checkable", "Manual Review", "total"],
    ):
        if status == "total":
            value = len(results)
            label_text = "Total rules"
        else:
            value = counts.get(status, counts.get(status.lower().replace(" ", "_"), 0))
            label_text = status
        col.metric(label_text, value)

    if platforms:
        st.caption("Platforms detected: " + ", ".join(str(p) for p in platforms))

    if results:
        st.markdown("#### Rule-by-rule results")
        status_filter = st.selectbox(
            "Filter by status",
            ["All", "Fail", "Pass", "Not Checkable", "Manual Review"],
            key="security_status_filter",
        )
        visible = [
            row for row in results
            if status_filter == "All" or row.get("status") == status_filter
        ]
        table_rows = []
        for row in visible:
            table_rows.append({
                "Rule ID": row.get("id", ""),
                "Platform": row.get("platform", ""),
                "Category": row.get("category", ""),
                "Rule": row.get("title", row.get("setting", "")),
                "Setting": row.get("setting", ""),
                "Expected": str(row.get("expected", "")),
                "Actual": str(row.get("actual", "")),
                "Severity": row.get("severity", ""),
                "Status": row.get("status", ""),
                "Reason": row.get("reason", ""),
            })
        st.dataframe(table_rows, use_container_width=True, hide_index=True)

        report = {
            "summary": counts,
            "platforms_checked": platforms,
            "results": results,
        }
        st.download_button(
            "Download scan report (JSON)",
            data=json.dumps(report, indent=2, default=str),
            file_name="security_scan_report.json",
            mime="application/json",
            key="download_security_scan",
        )
    else:
        st.warning("The evaluator returned no rule results. Check the uploaded files and evaluator output.")


def page_findings():
    if need_run("No results yet", "Upload a configuration on the Compare page and your findings will appear here."):
        return

    s = A[0]

    # Dedicated view for the built-in 106-rule security assessment.
    if s.get("mode") == "security":
        assessment = s["security_assessment"]
        counts = assessment.get("counts", {})
        results = assessment.get("results", [])

        h1, h2 = st.columns([5, 1.3], vertical_alignment="bottom")
        h1.markdown(
            result_head(
                s["name"],
                "Security Assessment",
                s["base_label"],
                fmt_date(s["last_scan"]),
            ),
            unsafe_allow_html=True,
        )
        h2.button(
            "New comparison",
            key="new_security_cmp",
            on_click=go,
            args=("compare",),
            use_container_width=True,
        )

        st.subheader("Built-in security baseline")
        st.caption(
            "All 106 rules are included. Rules without matching uploaded evidence "
            "are shown as Not Checkable or Manual Review, not treated as failures."
        )

        uploaded_files = s.get("uploaded_files", [])
        if uploaded_files:
            st.write("**Uploaded configuration files:**")
            for filename in uploaded_files:
                st.write(f"- {filename}")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Pass", counts.get("pass", 0))
        c2.metric("Fail", counts.get("fail", 0))
        c3.metric("Not Checkable", counts.get("not_checkable", 0))
        c4.metric("Manual Review", counts.get("manual_review", 0))

        st.caption(f"Total rules evaluated: {counts.get('total', len(results))} / 106")

        if results:
            platforms = ["All"] + sorted({
                row.get("platform", "Unknown") for row in results
            })
            statuses = ["All", "Pass", "Fail", "Not Checkable", "Manual Review"]

            f1, f2 = st.columns(2)
            selected_platform = f1.selectbox(
                "Filter by platform",
                platforms,
                key="security_findings_platform",
            )
            selected_status = f2.selectbox(
                "Filter by status",
                statuses,
                key="security_findings_status",
            )

            filtered = [
                row for row in results
                if (selected_platform == "All" or row.get("platform") == selected_platform)
                and (selected_status == "All" or row.get("status") == selected_status)
            ]

            st.caption(f"Showing {len(filtered)} of {len(results)} rules")

            st.dataframe(
                [
                    {
                        "Rule ID": row.get("id", ""),
                        "Platform": row.get("platform", ""),
                        "Category": row.get("category", ""),
                        "Title": row.get("title", ""),
                        "Setting": row.get("setting", ""),
                        "Expected": str(row.get("expected", "")),
                        "Actual": str(row.get("actual", "")),
                        "Severity": row.get("severity", ""),
                        "Status": row.get("status", ""),
                        "Reason": row.get("reason", ""),
                    }
                    for row in filtered
                ],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.warning("No security rule results were returned.")

        return

    h1, h2 = st.columns([5, 1.3], vertical_alignment="bottom")

    h1.markdown(result_head(s["name"], s["kind"], s["base_label"], fmt_date(s["last_scan"])), unsafe_allow_html=True)
    h2.button("New comparison", key="new_cmp", on_click=go, args=("compare",), use_container_width=True)

    ca, cb = st.columns([1, 2.2], gap="large")
    with ca:
        with st.container(key="card_ring"):
            H('<div class="center"><div class="card-title">Security posture</div>' + ring(s["score"]) +
              '<p class="formula">100 &minus; 15 High &minus; 7 Medium &minus; 2 Low</p></div>')
    with cb:
        with st.container(key="card_verdict"):
            H(verdict(s["findings"], len(s["baseline"])))
    st.write("")

    if s["mode"] == "standard":
        extra = ""
        if s["not_covered"]:
            extra += (f'<b>{len(s["not_covered"])}</b> setting{"" if len(s["not_covered"]) == 1 else "s"} in your file '
                      f'aren\'t covered by the standard baseline and were left out. ')
        extra += "Upload your own baseline to compare everything."
        H(f'<div class="note"><b>Checked {len(s["baseline"])} of {len(STANDARD_BASELINE)} standard settings.</b> {extra}</div>')
        if s["not_covered"]:
            with st.expander("Settings that weren't checked"):
                st.write(", ".join(f"`{k}`" for k in s["not_covered"]))
        st.write("")

    if s["mode"] == "custom":
        current_only = [(k, value) for k, value in s["current"].items() if k not in s["baseline"]]
        if current_only:
            H('<div class="card-title">Configurations Not Available in Baseline</div>')
            st.caption(
                "These settings are present in the current configuration but do not exist "
                "in the uploaded baseline, so they are not available for comparison. "
                "They are listed for information only and are not automatically marked as risky."
            )
            info_rows = []
            for setting, value in current_only:
                info_rows.append([
                    f'{esc(label(setting))}<span class="key">{esc(setting)}</span>',
                    chip(value, "", True),
                    '<span class="muted">Not available to compare with baseline.</span>',
                ])
            table(
                "current_only",
                [2, 1.2, 2.5],
                ["Setting", "Current value", "Comparison status"],
                info_rows,
            )
            st.write("")

    t_find, t_security, t_raw = st.tabs(["Findings", "Standard Security Review", "Raw data"])
    with t_find:
        e1, e2, e3, _ = st.columns([1, 1, 1.6, 2], vertical_alignment="bottom")
        xr = e1.selectbox("Risk", ["All", "High", "Medium", "Low"], key="x_risk")
        xt = e2.selectbox("Change", ["All", "Modified", "Added", "Removed"], key="x_type")
        xu = e3.checkbox("Show unchanged settings", key="x_unch")
        keys = list(dict.fromkeys(list(s["baseline"]) + list(s["current"])))
        fmap = {f["setting"]: f for f in s["findings"]}
        ordered = sorted(keys, key=lambda k: RISK_ORDER[fmap[k]["risk"]] if k in fmap else 9)
        rows = []
        for k in ordered:
            f = fmap.get(k)
            if not f and not xu:
                continue
            if xr != "All" and (not f or f["risk"] != xr):
                continue
            if xt != "All" and (not f or f["type"] != xt.lower()):
                continue
            typ = f["type"] if f else "same"
            rows.append([f'{esc(label(k))}<span class="key">{esc(k)}</span>',
                         chip(s["baseline"].get(k), "", k in s["baseline"]),
                         chip(s["current"].get(k), "t-" + typ if f else "", k in s["current"]),
                         type_badge(typ), risk_badge(f["risk"]) if f else '<span class="muted">&mdash;</span>',
                         status_badge(dstatus(f["id"])) if f else "",
                         review_btn(f["id"], "ex") if f else ""])
        if rows:
            table("explorer", [2.2, 1.6, 1.6, 1.1, 1, 1.1, 1],
                  ["Setting", "Baseline", "Current", "Change", "Risk", "Decision", ""], rows)
        elif not s["findings"] and xr == "All" and xt == "All":
            H(empty_clean("Everything matches the baseline."))
        else:
            H(empty("No settings match these filters"))

    with t_security:
        review = s.get("standard_security_review")
        review_error = s.get("standard_security_review_error", "")

        if review_error:
            st.warning(f"Standard security review could not be completed: {review_error}")
        elif review is None:
            st.info(
                "The standard SSH security review is available when both the current "
                "configuration and custom baseline are SSH files."
            )
        else:
            counts = review.get("counts", {})
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Pass", counts.get("pass", 0))
            c2.metric("Fail", counts.get("fail", 0))
            c3.metric("Not Checkable", counts.get("not_checkable", 0))
            c4.metric("Manual Review", counts.get("manual_review", 0))

            st.caption(
                "These results are evaluated against the standard security baseline. "
                "They are separate from your custom baseline findings and risk score."
            )

            results = review.get("results", [])
            if results:
                status_filter = st.selectbox(
                    "Filter standard security results",
                    ["All", "Pass", "Fail", "Not Checkable", "Manual Review"],
                    key="standard_security_filter",
                )
                filtered = [
                    row for row in results
                    if status_filter == "All" or row.get("status") == status_filter
                ]
                st.dataframe(
                    [
                        {
                            "Rule ID": row.get("id", ""),
                            "Category": row.get("category", ""),
                            "Setting": row.get("setting", ""),
                            "Expected": str(row.get("expected", "")),
                            "Actual": str(row.get("actual", "")),
                            "Severity": row.get("severity", ""),
                            "Status": row.get("status", ""),
                            "Reason": row.get("reason", ""),
                        }
                        for row in filtered
                    ],
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No standard security rules were evaluated.")

    with t_raw:
        r1, r2 = st.columns(2)
        base_title = "baseline" if s["mode"] == "custom" else "standard baseline"
        r1.markdown(f'<div class="code-title">{base_title} <span class="muted">&middot; approved</span></div>' +
                    raw_json(s["baseline"], s["findings"]), unsafe_allow_html=True)
        r2.markdown(f'<div class="code-title">{esc(s["name"])} <span class="muted">&middot; observed</span></div>' +
                    raw_json(s["current"], s["findings"]), unsafe_allow_html=True)
        H('<p class="hint">Highlighted lines differ from the baseline. SSH files are shown as normalised settings.</p>')


def page_remediation():
    H('<div class="res-head"><div class="eyebrow"><i></i>REMEDIATION</div><h1 style="font-family:var(--display)">Review proposed fixes</h1>'
      '<p class="sub muted" style="margin-top:8px">Approving records your decision only. Nothing is changed on any server.</p></div>')

    if need_run("Nothing to review yet", "Once a comparison finds drift, proposed fixes will be listed here."):
        return

    if ss.run.get("mode") == "security":
        st.info(
            "The built-in 106-rule security assessment provides security findings "
            "and verification results. The remediation approval workflow is "
            "available for custom-baseline drift comparisons."
        )
        return

    n = {"Pending": 0, "Approved": 0, "Rejected": 0}
    for f in T["all"]:
        n[dstatus(f["id"])] += 1
    H('<div class="mini-row">' + "".join(f'<div class="mini"><b>{v}</b><span class="muted">{k}</span></div>'
                                          for k, v in n.items()) + "</div>")
    if not T["all"]:
        H(empty_clean("There are no findings to remediate."))
        return
    flt = st.selectbox("Status", ["All", "Pending", "Approved", "Rejected"], key="f_rem")
    order = {"Pending": 0, "Approved": 1, "Rejected": 2}
    rows = [f for f in T["all"] if flt == "All" or dstatus(f["id"]) == flt]
    rows.sort(key=lambda f: (order[dstatus(f["id"])], RISK_ORDER[f["risk"]]))
    if not rows:
        H(empty("Nothing to show", "No findings match this status."))
        return
    out = []
    for f in rows:
        d = ss.decisions.get(f["id"], {})
        out.append([f'{esc(label(f["setting"]))}<span class="key">{esc(f_expected(f))} &rarr; {esc(f_actual(f))}</span>',
                    risk_badge(f["risk"]), status_badge(dstatus(f["id"])), esc(d.get("by", "—")),
                    fmt_date(d["at"]) if d.get("at") else "—",
                    f'<span class="muted">{esc(d.get("note") or "—")}</span>', review_btn(f["id"], "rem")])
    table("rem", [2.4, 1, 1.1, 0.9, 1.4, 2, 1], ["Setting", "Risk", "Status", "Decided by", "When", "Note", ""], out)


def print_report_html() -> str:
    parts = [f'<div class="print-report"><h1>Configuration Drift Report</h1><p>Generated {datetime.now():%d %b %Y, %I:%M %p} &middot; '
             f'{T["total"]} drifts (High {T["c"]["High"]}, Medium {T["c"]["Medium"]}, Low {T["c"]["Low"]}) '
             f'&middot; posture {T["posture"]}/100</p>']
    for s in A:
        parts.append(f'<h2>{esc(s["name"])} vs {esc(s["base_label"])}</h2>')
        if s["findings"]:
            parts.append("<table><thead><tr><th>Setting</th><th>Change</th><th>Expected</th><th>Actual</th><th>Risk</th><th>Status</th></tr></thead><tbody>" +
                         "".join(f'<tr><td>{esc(label(f["setting"]))}</td><td>{TYPE_LABEL[f["type"]]}</td><td>{esc(f_expected(f))}</td>'
                                 f'<td>{esc(f_actual(f))}</td><td>{f["risk"]}</td><td>{dstatus(f["id"])}</td></tr>' for f in s["findings"]) +
                         "</tbody></table>")
        else:
            parts.append("<p>No drift detected.</p>")
    parts.append("<p style='margin-top:14pt;font-size:9pt'>Detection and risk are rule-based. AI only explains verified findings. A person approves every fix.</p></div>")
    return "".join(parts)


def page_reports():
    H('<div class="res-head"><div class="eyebrow"><i></i>REPORTS</div><h1 style="font-family:var(--display)">Export and history</h1>'
      '<p class="sub muted" style="margin-top:8px">Download the current findings and review earlier comparisons from this session.</p></div>')
    if need_run("No reports yet", "Run a comparison first, then export it here as JSON, CSV or PDF."):
        return

    if ss.run.get("mode") == "security":
        import csv
        import io

        from xml.sax.saxutils import escape

        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import landscape, letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
        )

        assessment = ss.run["security_assessment"]
        counts = assessment.get("counts", {})
        results = assessment.get("results", [])

        report = {
            "report_type": "Built-in 106-rule security assessment",
            "generated_at": ss.run["last_scan"],
            "uploaded_files": ss.run.get("uploaded_files", []),
            "baseline": "Built-in security baseline v1.0",
            "counts": counts,
            "results": results,
        }

        st.subheader("106-rule Security Assessment Report")
        st.caption(
            "This report contains the complete built-in security assessment. "
            "It does not use the custom drift-risk score."
        )

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Pass", counts.get("pass", 0))
        c2.metric("Fail", counts.get("fail", 0))
        c3.metric("Not Checkable", counts.get("not_checkable", 0))
        c4.metric("Manual Review", counts.get("manual_review", 0))

        st.caption(f"Total rules: {counts.get('total', len(results))} / 106")

        # CSV report
        csv_buffer = io.StringIO()

        fields = [
            "id", "platform", "category", "title", "setting",
            "expected", "actual", "severity", "status", "reason",
        ]

        writer = csv.DictWriter(
            csv_buffer,
            fieldnames=fields,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(results)

        # PDF report
        pdf_buffer = io.BytesIO()

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontSize=17,
            alignment=TA_CENTER,
            spaceAfter=12,
        )

        heading_style = ParagraphStyle(
            "ReportHeading",
            parent=styles["Heading2"],
            fontSize=11,
            spaceBefore=10,
            spaceAfter=6,
        )

        normal_style = ParagraphStyle(
            "ReportNormal",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
        )

        cell_style = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontSize=5.5,
            leading=7,
            wordWrap="CJK",
        )

        header_style = ParagraphStyle(
            "TableHeader",
            parent=cell_style,
            textColor=colors.white,
            fontName="Helvetica-Bold",
        )

        def pdf_text(value):
            if isinstance(value, (dict, list)):
                value = json.dumps(value, default=str)
            if value is None:
                value = "Not available"
            return Paragraph(escape(str(value)), cell_style)

        story = [
            Paragraph("Drift Detector - Security Assessment Report", title_style),
            Paragraph(
                "Built-in security baseline: Version 1.0 | "
                "Total rules: 106",
                normal_style,
            ),
            Spacer(1, 10),
            Paragraph("Assessment Summary", heading_style),
        ]

        uploaded_files = ss.run.get("uploaded_files", [])

        story.append(
            Paragraph(
                "Uploaded files: " + escape(", ".join(uploaded_files)),
                normal_style,
            )
        )

        story.append(
            Paragraph(
                "Generated: " + escape(str(ss.run["last_scan"])),
                normal_style,
            )
        )

        summary_data = [
            ["Pass", "Fail", "Not Checkable", "Manual Review", "Total"],
            [
                str(counts.get("pass", 0)),
                str(counts.get("fail", 0)),
                str(counts.get("not_checkable", 0)),
                str(counts.get("manual_review", 0)),
                str(counts.get("total", len(results))),
            ],
        ]

        summary_table = Table(summary_data, colWidths=[1.3 * inch] * 5)

        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263445")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#EDF2F7")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))

        story.extend([
            Spacer(1, 10),
            summary_table,
            Spacer(1, 14),
            Paragraph("Complete Security Rule Results", heading_style),
        ])

        pdf_fields = [
            "id", "platform", "category", "title", "setting",
            "expected", "actual", "severity", "status", "reason",
        ]

        table_data = [
            [
                Paragraph(escape(field.replace("_", " ").title()), header_style)
                for field in pdf_fields
            ]
        ]

        for result in results:
            table_data.append([
                pdf_text(result.get(field))
                for field in pdf_fields
            ])

        column_widths = [
            0.45 * inch,
            0.65 * inch,
            0.65 * inch,
            0.9 * inch,
            0.85 * inch,
            0.65 * inch,
            0.65 * inch,
            0.5 * inch,
            0.65 * inch,
            1.25 * inch,
        ]

        results_table = Table(
            table_data,
            colWidths=column_widths,
            repeatRows=1,
        )

        results_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263445")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))

        story.append(results_table)

        pdf = SimpleDocTemplate(
            pdf_buffer,
            pagesize=landscape(letter),
            rightMargin=0.3 * inch,
            leftMargin=0.3 * inch,
            topMargin=0.4 * inch,
            bottomMargin=0.4 * inch,
        )

        pdf.build(story)

        # Download buttons
        d1, d2, d3 = st.columns(3)

        d1.download_button(
            "Download JSON",
            data=json.dumps(report, indent=2, default=str),
            file_name="security_assessment_report.json",
            mime="application/json",
            key="download_security_assessment_json",
        )

        d2.download_button(
            "Download CSV",
            data=csv_buffer.getvalue(),
            file_name="security_assessment_report.csv",
            mime="text/csv",
            key="download_security_assessment_csv",
        )

        d3.download_button(
            "Download PDF",
            data=pdf_buffer.getvalue(),
            file_name="security_assessment_report.pdf",
            mime="application/pdf",
            key="download_security_assessment_pdf",
        )

        st.subheader("Assessment results")

        if results:
            st.dataframe(
                results,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.warning("No security results are available.")

        return

    with st.container(key="card_download"):
        H('<div class="card-title" style="margin:0">Download report</div>')
        st.caption("Includes every finding, its risk, and your approval decisions.")
        d1, d2, d3, _ = st.columns([1, 1, 1.6, 3])
        d1.download_button("JSON", json.dumps(report_data(A, ss.decisions), indent=2, default=str),
                           "drift_report.json", "application/json", icon=":material/download:", key="dl_json")
        d2.download_button("CSV", report_csv(A, ss.decisions), "drift_report.csv", "text/csv",
                           icon=":material/download:", key="dl_csv")
        if d3.button("Print / save as PDF", icon=":material/print:", key="print_btn"):
            ss.do_print = True
    st.write("")
    body = "".join(
        f'<tr><td>{fmt_date(p["time"])}</td><td><span class="mono">{esc(p["name"])}</span></td><td>{esc(p["against"])}</td>'
        f'<td class="num"><b>{p["drifts"]}</b></td><td class="num">{p["high"]}</td><td class="num">{p["score"]}</td></tr>'
        for p in reversed(ss.history))
    H('<div class="card-title">Comparisons this session</div><div class="table-wrap"><table>'
      '<thead><tr><th>Time</th><th>File</th><th>Compared with</th><th class="num">Drifts</th><th class="num">High</th>'
      f'<th class="num">Score</th></tr></thead><tbody>{body}</tbody></table></div>')
    if len(ss.history) > 1:
        st.write("")
        with st.container(key="card_trend"):
            H('<div class="card-title">Drift trend <small>Total drifts per comparison</small></div>' + trend(ss.history))
    st.markdown(print_report_html(), unsafe_allow_html=True)
    if ss.pop("do_print", False):
        components.html("<script>window.parent.print()</script>", height=0)


# ================================================================= review drawer
@st.cache_data(show_spinner=False)
def cached_explanation(f: dict) -> dict:
    return explain(f)


@st.dialog("Finding details", width="large")
def review_dialog(fid: str):
    hit = BY_ID.get(fid)
    if not hit:
        st.write("This finding is no longer available.")
        return
    f, s = hit
    with st.spinner("Loading explanation…"):
        exp = cached_explanation({k: f[k] for k in ("setting", "type", "expected", "actual", "risk")})
    d = ss.decisions.get(fid)
    e_chip, a_chip = finding_chips(f)
    after = '<span class="chip none">remove setting</span>' if f["type"] == "added" else e_chip
    H(f'<div class="drawer-head"><div class="eyebrow">{esc(s["name"])}</div><h2>{esc(label(f["setting"]))}</h2>'
      f'<code>{esc(f["setting"])}</code></div>'
      f'<div class="badges">{risk_badge(f["risk"])}{type_badge(f["type"])}{status_badge(dstatus(fid))}</div>'
      '<div class="sec" style="margin-top:0">Evidence<span class="tag tag-rule">Rule-based</span></div>'
      f'<div class="evidence"><div class="box"><div class="lbl">Expected (baseline)</div>{e_chip}</div><div class="arr">&rarr;</div>'
      f'<div class="box"><div class="lbl">Actual (observed)</div>{a_chip}</div></div>'
      '<div class="sec">Before / after fix</div>'
      f'<div class="evidence"><div class="box"><div class="lbl">Now</div>{a_chip}</div><div class="arr">&rarr;</div>'
      f'<div class="box"><div class="lbl">After fix</div>{after}</div></div>'
      '<p class="hint">Proposed state only. Nothing is changed on the server.</p>'
      f'<div class="sec">Explanation<span class="tag tag-ai">{esc(exp["source"])}</span></div>'
      f'<div class="exp-block"><h4>Why it matters</h4><p>{rich(exp["why_it_matters"])}</p></div>'
      f'<div class="exp-block"><h4>Impact</h4><p>{rich(exp["impact"])}</p></div>'
      f'<div class="exp-block"><h4>Suggested fix</h4><div class="fixbox">{rich(exp["suggested_fix"])}</div></div>')
    st.divider()
    if not d:
        H('<div class="sec" style="margin-top:0">Your decision</div>')
        st.text_area("Note", key=f"note_{fid}", placeholder="Optional note (why you approve or reject)",
                     label_visibility="collapsed")
        b1, b2 = st.columns(2)
        if b1.button("Approve fix", type="primary", key=f"ap_{fid}"):
            decide(fid, "Approved")
        if b2.button("Reject", key=f"rj_{fid}"):
            decide(fid, "Rejected")
        H('<p class="hint">Approving only records your decision. The tool never changes a server.</p>')
    else:
        note = f'<p style="margin-top:8px">“{esc(d["note"])}”</p>' if d.get("note") else ""
        H(f'<div class="sec" style="margin-top:0">Your decision</div><div class="decided">{status_badge(d["status"])} '
          f'by <b>{esc(d["by"])}</b> &middot; {fmt_date(d["at"])}{note}</div>')
        if st.button("Reopen", key=f"ro_{fid}"):
            decide(fid, "Pending")


# ================================================================= router
{
    "compare": page_compare,
    "security_scan": page_security_scan,
    "findings": page_findings,
    "remediation": page_remediation,
    "reports": page_reports,
}.get(ss.page, page_compare)()
H(FOOTER)

rid = ss.pop("review_id", None)
if rid:
    review_dialog(rid)