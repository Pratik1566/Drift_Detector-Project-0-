"""UI helpers and architectural dark visual system for Drift Detector."""

import html
import json
import math
from datetime import datetime

from core import DOT, TYPE_LABEL, label, plain, RISK_RULES, STANDARD_BASELINE
from security_baseline import BASELINE_COUNTS, STANDARD_SECURITY_BASELINE

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def esc(s) -> str:
    return html.escape("" if s is None else str(s), quote=True).replace("$", "&#36;")


def rich(text: str) -> str:
    """Escape text and render backtick-wrapped content as code."""
    out, parts = [], esc(text).split("`")
    for i, part in enumerate(parts):
        out.append(f"<code>{part}</code>" if i % 2 else part)
    return "".join(out)


def time_ago(dt: datetime) -> str:
    seconds = (datetime.now() - dt).total_seconds()

    if seconds < 60:
        return "just now"

    minutes = seconds / 60
    if minutes < 60:
        return f"{round(minutes)} min ago"

    hours = minutes / 60
    if hours < 24:
        return f"{round(hours)} h ago"

    return f"{round(hours / 24)} d ago"


def fmt_date(dt) -> str:
    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt)
    return dt.strftime("%b %d, %I:%M %p")


def kind_label(kind: str) -> str:
    return {
        "json": "JSON",
        "ssh": "SSH config",
        "standard": "Standard",
    }.get(kind, kind)


def risk_badge(r: str) -> str:
    return (
        f'<span class="badge {esc(r)}">'
        f'<i></i>{"Clean" if r == "None" else esc(r)}</span>'
    )


def type_badge(t: str) -> str:
    return f'<span class="badge t-{esc(t)}">{esc(TYPE_LABEL[t])}</span>'


def status_badge(s: str) -> str:
    return f'<span class="badge s-{esc(s)}">{esc(s)}</span>'


def chip(value, cls: str = "", present: bool = True) -> str:
    if not present:
        return '<span class="chip none">not set</span>'

    return (
        f'<span class="chip {esc(cls)}">'
        f'{esc(plain(value))}</span>'
    )


def finding_chips(f):
    """Return expected and actual value chips for a finding."""
    return (
        chip(f["expected"], "", f["type"] != "added"),
        chip(f["actual"], "t-" + f["type"], f["type"] != "removed"),
    )


def pill(text: str, cls: str = "") -> str:
    return f'<span class="pill {esc(cls)}">{esc(text)}</span>'


# ---------------------------------------------------------------------------
# Reusable HTML blocks
# ---------------------------------------------------------------------------

_ICON = (
    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" '
    'stroke="currentColor" stroke-width="1.75" '
    'stroke-linecap="round" stroke-linejoin="round">{}</svg>'
)


def hero() -> str:
    return (
        '<div class="hero">'
        '<div class="hero-pill">'
        '<span>CONFIGURATION INTELLIGENCE</span>'
        '<span class="pill-ver">v2.4.11</span>'
        '</div>'
        '<h1>See what changed. '
        '<span class="grad">Know what matters.</span></h1>'
        '<p class="hero-sub">'
        'Compare live server configurations against trusted production baselines '
        'or audit deterministically against 106 built-in infrastructure security controls.'
        '</p>'
        '<div class="hero-telemetry">'
        '<span><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#F87171" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M9 12l2 2 4-4"/></svg>106 Rules Active</span>'
        '<span class="sep">&bull;</span>'
        '<span><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#46EDE0" stroke-width="2"><path d="M12 3l8 3v6c0 4.5-3.2 8.2-8 9-4.8-.8-8-4.5-8-9V6z"/></svg>CIS Ubuntu 22.04 Level 2</span>'
        '<span class="sep">&bull;</span>'
        '<span><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#93C5FD" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 9h6v6H9z"/></svg>Zero Data Ingestion / Client-Side Diff</span>'
        '</div>'
        '</div>'
    )


def step_head(n: str, title: str, tag: str, tag_cls: str, desc: str) -> str:
    formats = (
        '<span>JSON</span><span>sshd_config</span><span>nginx.conf</span><span>sysctl.conf</span>'
        if tag_cls == "req"
        else '<span>JSON</span><span>sshd_config</span><span class="muted-tag">git commit ref</span><span class="muted-tag">CIS v2.0 Rulepack</span>'
    )
    corner_icon = (
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><circle cx="7" cy="7" r="1" fill="currentColor"/><circle cx="7" cy="17" r="1" fill="currentColor"/></svg>'
        if tag_cls == "req"
        else '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 3l8 3v6c0 4.5-3.2 8.2-8 9-4.8-.8-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>'
    )
    return (
        f'<div class="step">'
        f'<div class="step-top">'
        f'<span class="step-n"><i></i>0{esc(n)} &bull; {esc(tag).upper()}</span>'
        f'<span class="step-ic">{corner_icon}</span>'
        f'</div>'
        f'<h3>{esc(title)}</h3>'
        f'<p>{esc(desc)}</p>'
        f'<div class="fmt">{formats}</div>'
        f'</div>'
    )


def ready_line(msg_html: str, ok: bool) -> str:
    return (
        f'<div class="ready {"ok" if ok else ""}">'
        f'<i></i><span>{msg_html}</span></div>'
    )


def features() -> str:
    items = [
        (
            _ICON.format('<path d="M4 6h16M4 12h16M4 18h10"/>'),
            "01 / DETERMINISTIC",
            "Rules decide",
            "Every setting is evaluated using defined benchmark rules. Nothing is guessed.",
        ),
        (
            _ICON.format(
                '<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17'
                'l-1.8-5.2L5 10l5.2-1.8z"/>'
            ),
            "02 / CONTEXTUAL",
            "AI explains",
            "Understand verified drift findings with clear security impact and remediation context.",
        ),
        (
            _ICON.format(
                '<circle cx="12" cy="12" r="9"/>'
                '<path d="M8.5 12.5l2.5 2.5 4.5-5"/>'
            ),
            "03 / HUMAN-IN-THE-LOOP",
            "You approve",
            "Every proposed fix requires your explicit review and decision. No server is ever modified.",
        ),
    ]

    return (
        '<div class="features">'
        + "".join(
            f'<div class="feat">'
            f'<div class="feat-ic">{ic}</div>'
            f'<div class="feat-tag">{tg}</div>'
            f'<h4>{tt}</h4>'
            f'<p>{ds}</p>'
            f'</div>'
            for ic, tg, tt, ds in items
        )
        + "</div>"
    )

def baseline_table() -> str:
    """Display the complete built-in 106-rule security baseline."""

    platform_names = {
        "ubuntu_22_04": "Ubuntu 22.04",
        "ssh": "SSH Server",
        "nginx": "NGINX",
    }

    parts = [
        '<div class="baseline-overview">',
        '<div class="baseline-summary">',
        '<div><strong>106</strong><span>Total rules</span></div>',
        f'<div><strong>{BASELINE_COUNTS["automatic"]}</strong><span>Automatic</span></div>',
        f'<div><strong>{BASELINE_COUNTS["manual"]}</strong><span>Manual review</span></div>',
        '</div>',
        '<p class="hint">Built-in security baseline &middot; Version '
        f'{esc("1.0")}</p>',
        '</div>',
    ]

    for platform_key, rules in STANDARD_SECURITY_BASELINE.items():
        platform_name = platform_names.get(
            platform_key,
            platform_key.replace("_", " ").title(),
        )

        automatic_count = sum(1 for rule in rules if rule["automatic"])
        manual_count = len(rules) - automatic_count

        parts.append(
            '<div class="baseline-platform">'
            f'<div class="baseline-platform-heading">'
            f'<h3>{esc(platform_name)}</h3>'
            f'<span class="muted">{len(rules)} rules</span>'
            '</div>'
            f'<p class="hint">{automatic_count} automatic &middot; '
            f'{manual_count} manual review</p>'
            '<div class="table-wrap"><table>'
            '<thead><tr>'
            '<th>Rule ID</th>'
            '<th>Security rule</th>'
            '<th>Setting</th>'
            '<th>Expected</th>'
            '<th>Severity</th>'
            '<th>Evaluation</th>'
            '</tr></thead><tbody>'
        )

        for rule in rules:
            evaluation = (
                '<span class="baseline-auto">Automatic</span>'
                if rule["automatic"]
                else '<span class="baseline-manual">Manual review</span>'
            )

            expected = rule["expected"]
            if isinstance(expected, (dict, list)):
                expected = json.dumps(expected)

            parts.append(
                '<tr>'
                f'<td><span class="mono">{esc(rule["id"])}</span></td>'
                f'<td><b>{esc(rule["title"])}</b>'
                f'<div class="muted">{esc(rule["category"])}</div></td>'
                f'<td><span class="key">{esc(rule["setting"])}</span></td>'
                f'<td>{chip(expected)}</td>'
                f'<td>{risk_badge(rule["severity"])}</td>'
                f'<td>{evaluation}</td>'
                '</tr>'
            )

        parts.append('</tbody></table></div></div>')

    return ''.join(parts)


def empty_state(title: str, msg: str) -> str:
    return (
        '<div class="empty-state">'
        '<div class="big">'
        '<svg width="28" height="28" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="1.6" '
        'stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M5 4h10l4 4v12H5z"/>'
        '<path d="M15 4v4h4"/><path d="M9 13h6M9 17h4"/>'
        '</svg></div>'
        f'<h3>{esc(title)}</h3><p>{esc(msg)}</p></div>'
    )


def empty_clean(msg: str) -> str:
    return (
        '<div class="empty-state ok">'
        '<div class="big">'
        '<svg width="28" height="28" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="1.8" '
        'stroke-linecap="round" stroke-linejoin="round">'
        '<circle cx="12" cy="12" r="9"/>'
        '<path d="M8.5 12.5l2.5 2.5 4.5-5"/>'
        '</svg></div>'
        '<h3>No drift detected</h3>'
        f'<p>{esc(msg)}</p></div>'
    )


def empty(title: str, msg: str = "") -> str:
    return (
        f'<div class="empty-state">'
        f'<h3>{esc(title)}</h3><p>{esc(msg)}</p></div>'
    )


def result_head(name: str, kind: str, base_label: str, when: str) -> str:
    return (
        '<div class="res-head">'
        '<div class="eyebrow"><i></i>COMPARISON RESULT</div>'
        f'<h1>{esc(name)}</h1>'
        f'<div class="res-meta">{pill(kind_label(kind))}'
        f'<span class="vs">compared with</span>'
        f'{pill(base_label, "accent")}'
        f'<span class="vs">&middot; {esc(when)}</span>'
        '</div></div>'
    )


def verdict(findings: list, checked: int) -> str:
    count = len(findings)
    high = sum(1 for f in findings if f["risk"] == "High")

    if not count:
        title = "All clear."
        sub = f"All {checked} checked settings match the baseline."
        badge = '<span class="verdict-tag ok">COMPLIANT</span>'
    elif high:
        title = f"{high} critical change{'' if high == 1 else 's'} need{'' if high != 1 else 's'} attention."
        sub = (
            f"{count} structural difference{'' if count == 1 else 's'} "
            f"found across {checked} checked settings."
        )
        badge = '<span class="verdict-tag crit">ACTION REQUIRED</span>'
    else:
        title = f"{count} change{'' if count == 1 else 's'} found."
        sub = f"None are high risk. {checked} settings were checked."
        badge = '<span class="verdict-tag warn">REVIEW ADVISED</span>'

    counts = {
        risk: sum(1 for f in findings if f["risk"] == risk)
        for risk in ("High", "Medium", "Low")
    }

    stats = "".join(
        f'<div class="stat-box">'
        f'<div class="stat-l"><i style="background:{DOT[risk]}"></i>{risk.upper()} RISK</div>'
        f'<div class="stat-n">{counts[risk]}</div>'
        f'</div>'
        for risk in counts
    )

    return (
        f'<div class="verdict">'
        f'<div class="verdict-top"><div><h2>{esc(title)}</h2><p>{esc(sub)}</p></div>{badge}</div>'
        f'<div class="stats">{stats}</div>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# SVG charts
# ---------------------------------------------------------------------------

def ring(score: int) -> str:
    circumference = 2 * math.pi * 56
    color = (
        "#10B981" if score >= 80
        else "#F59E0B" if score >= 50
        else "#EF4444"
    )
    risk_txt = (
        "LOW RISK" if score >= 80
        else "MODERATE RISK" if score >= 50
        else "CRITICAL RISK"
    )
    risk_cls = (
        "low" if score >= 80
        else "med" if score >= 50
        else "high"
    )

    return (
        f'<svg class="ring" viewBox="0 0 140 140" role="img" '
        f'aria-label="Posture score {score} out of 100">'
        '<circle cx="70" cy="70" r="56" fill="none" '
        'stroke="#1F2B2B" stroke-width="9"/>'
        f'<circle class="ring-arc" cx="70" cy="70" r="56" fill="none" '
        f'stroke="{color}" stroke-width="9" stroke-linecap="round" '
        f'stroke-dasharray="{circumference * score / 100:.2f} '
        f'{circumference:.2f}" transform="rotate(-90 70 70)"/>'
        f'<text x="70" y="75" text-anchor="middle" '
        f'class="r-num">{score}</text>'
        '<text x="70" y="94" text-anchor="middle" '
        'class="r-lbl">/ 100</text></svg>'
        f'<div class="ring-pill {risk_cls}"><i></i>{risk_txt}</div>'
    )


def trend(points: list[dict]) -> str:
    if not points:
        return ""

    width, height, padding = 460, 160, 28
    maximum = max([1] + [p["drifts"] for p in points])
    count = len(points)

    def x_pos(i):
        fraction = 0.5 if count == 1 else i / (count - 1)
        return padding + (width - 2 * padding) * fraction

    def y_pos(value):
        return height - padding - (
            (height - 2 * padding) * value / maximum
        )

    line = " ".join(
        f"{x_pos(i):.1f},{y_pos(p['drifts']):.1f}"
        for i, p in enumerate(points)
    )

    dots = "".join(
        f'<line x1="{x_pos(i):.1f}" y1="{y_pos(p["drifts"]):.1f}" '
        f'x2="{x_pos(i):.1f}" y2="{height - padding}" '
        'stroke="#10B981" stroke-opacity="0.25" stroke-dasharray="2 2"/>'
        f'<circle cx="{x_pos(i):.1f}" '
        f'cy="{y_pos(p["drifts"]):.1f}" r="4.5" fill="#0B0E0E" stroke="#10B981" stroke-width="2.2"/>'
        f'<text x="{x_pos(i):.1f}" '
        f'y="{y_pos(p["drifts"]) - 10:.1f}" '
        f'text-anchor="middle" font-size="11" '
        f'fill="#F3F7F7" font-family="JetBrains Mono, monospace" font-weight="600">{p["drifts"]}</text>'
        for i, p in enumerate(points)
    )

    labels = "".join(
        f'<text x="{x_pos(i):.1f}" y="{height - 6}" '
        f'text-anchor="middle" font-size="10" font-family="JetBrains Mono, monospace" fill="#8B949E">'
        f'{esc(p["time"].strftime("%H:%M"))}</text>'
        for i, p in enumerate(points)
    )

    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        'role="img" aria-label="Drift count across comparisons">'
        f'<line x1="{padding}" y1="{height - padding}" '
        f'x2="{width - padding}" y2="{height - padding}" '
        'stroke="#1F2B2B"/>'
        f'<polyline points="{line}" fill="none" '
        'stroke="#10B981" stroke-width="2.2" '
        'stroke-linejoin="round" stroke-linecap="round"/>'
        f'{dots}{labels}</svg>'
    )


def raw_json(obj: dict, drifts: list[dict]) -> str:
    by = {d["setting"]: d["type"] for d in drifts}
    keys = list(obj)
    lines = ""

    for i, key in enumerate(keys):
        value = json.dumps(obj[key]).replace(",", ", ")
        txt = f'  "{key}": {value}'
        if i < len(keys) - 1:
            txt += ","

        cls = f" d-{by[key]}" if key in by else ""
        lines += f'<span class="ln{cls}">{esc(txt)}</span>'

    return (
        '<div class="code">'
        '<span class="ln">{</span>'
        f'{lines}'
        '<span class="ln">}</span>'
        '</div>'
    )


# ---------------------------------------------------------------------------
# Brand, session pill, and footer
# ---------------------------------------------------------------------------

BRAND = (
    '<div class="brand">'
    '<span class="logo">'
    '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" '
    'stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 3l8 3v6c0 4.5-3.2 8.2-8 9-4.8-.8-8-4.5-8-9V6z"/>'
    '<path d="M9 12l2 2 4-4"/></svg></span>'
    '<span class="brand-name">Drift<span class="brand-dot">.</span></span>'
    '</div>'
)


def session_pill(run: dict | None) -> str:
    if run:
        return (
            '<div class="nav-session active">'
            '<span class="s-dot ok"></span>'
            f'<span class="s-file">{esc(run["name"])}</span>'
            f'<span class="s-time">&middot; {time_ago(run["last_scan"])}</span>'
            '</div>'
        )
    return (
        '<div class="nav-session">'
        '<span class="s-dot idle"></span>'
        '<span class="s-file">No active session</span>'
        '</div>'
    )


FOOTER = (
    '<div class="foot">'
    '<div class="foot-inner">'
    '<span>Drift &middot; Configuration Intelligence</span>'
    '<span class="foot-badge"><i></i>Detection and risk are rule-based &middot; AI only explains verified findings</span>'
    '<span class="foot-status"><i></i>SYSTEM READY</span>'
    '</div>'
    '</div>'
)


# ---------------------------------------------------------------------------
# Obsidian + Teal Architectural Theme CSS (Stitch-derived, restrained hover)
# ---------------------------------------------------------------------------

CSS = r"""
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

:root {
    color-scheme: dark;

    --bg: #0B0E0E;
    --surface: #111616;
    --surface-low: #161B1C;
    --alt: #181E1F;
    --raised: #1D2425;
    --hover: #222B2C;

    --ink: #F3F7F7;
    --ink-2: #C6D0D0;
    --muted: #8B949E;

    --line: #283636;
    --line-2: #1F2B2B;

    --accent: #10B981;
    --accent-cyan: #46EDE0;
    --accent-h: #14C98E;
    --accent-50: rgba(16, 185, 129, 0.11);
    --accent-ink: #46EDE0;

    --high: #EF4444;
    --high-bg: rgba(239, 68, 68, 0.12);
    --high-line: rgba(239, 68, 68, 0.30);

    --medium: #F59E0B;
    --medium-bg: rgba(245, 158, 11, 0.12);
    --medium-line: rgba(245, 158, 11, 0.30);

    --low: #10B981;
    --low-bg: rgba(16, 185, 129, 0.12);
    --low-line: rgba(16, 185, 129, 0.28);

    --t-modified: #46EDE0;
    --t-modified-bg: rgba(70, 237, 224, 0.11);
    --t-added: #10B981;
    --t-added-bg: rgba(16, 185, 129, 0.12);
    --t-removed: #ADC6FF;
    --t-removed-bg: rgba(173, 198, 255, 0.12);

    --radius: 12px;
    --radius-sm: 8px;

    --mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    --sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    --display: 'Space Grotesk', 'Inter', sans-serif;
}

/* ---------- subtle architectural entrance animations ---------- */

@keyframes fadeSlideUp {
    from {
        opacity: 0;
        transform: translateY(8px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes statusPulse {
    0%, 100% {
        opacity: 1;
        transform: scale(1);
    }
    50% {
        opacity: 0.45;
        transform: scale(0.88);
    }
}

html, body, [class*="st-"], .stApp {
    font-family: var(--sans);
    -webkit-font-smoothing: antialiased;
}

/* ---------- obsidian canvas + 48px architectural grid + top radial glow ---------- */

.stApp {
    background-color: var(--bg);
    background-image:
        radial-gradient(ellipse 68% 36% at 50% 0%, rgba(16, 185, 129, 0.085) 0%, rgba(11, 14, 14, 0) 72%),
        linear-gradient(to right, rgba(255, 255, 255, 0.035) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(255, 255, 255, 0.035) 1px, transparent 1px);
    background-size: 100% 100%, 48px 48px, 48px 48px;
    background-position: top center, top center, top center;
    color: var(--ink);
}

[data-testid="stMainBlockContainer"] {
    max-width: 1220px;
    padding: 1.2rem 2rem 3.5rem;
    animation: fadeSlideUp 0.28s ease-out;
}

h1, h2, h3, h4 {
    font-family: var(--display);
    margin: 0;
    padding: 0;
    color: inherit;
}

p {
    margin: 0;
    padding: 0;
    color: inherit;
}

code, .mono {
    font-family: var(--mono);
}

.muted {
    color: var(--muted);
}

/* Hide default Streamlit chrome & sidebar */
[data-testid="stHeader"],
section[data-testid="stSidebar"],
[data-testid="collapsedControl"],
[data-testid="stToolbar"],
[data-testid="stDecoration"],
.stDeployButton,
#MainMenu,
footer {
    display: none !important;
}

[data-testid="stIconMaterial"],
span[class*="material"] {
    font-family: 'Material Symbols Rounded',
                 'Material Symbols Outlined' !important;
}

/* ---------- top navigation bar ---------- */

.st-key-topnav {
    position: sticky;
    top: 0;
    z-index: 100;
    background: rgba(11, 14, 14, 0.88);
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    border-bottom: 1px solid var(--line-2);
    padding: 12px 24px;
    margin: -1.2rem -2rem 1.4rem;
}

.st-key-topnav [data-testid="stHorizontalBlock"] {
    align-items: center;
}

# .st-key-topnav [data-testid="stMarkdownContainer"] p {
#     margin: 0 !important;
#     line-height: 1 !important;
# }

# .st-key-topnav .brand,
# .st-key-topnav .nav-session {
#     position: relative;
#     top: -2px;
# }

.st-key-topnav .stButton > button {
    border: 1px solid transparent;
    background: transparent;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 0.78rem;
    font-weight: 500;
    letter-spacing: 0.02em;
    border-radius: 6px;
    padding: 0.38rem 0.72rem;
    min-height: 0;
    white-space: nowrap;
    transition: background 0.16s ease, color 0.16s ease, border-color 0.16s ease;
}

.st-key-topnav .stButton > button:hover {
    background: var(--raised);
    color: var(--ink);
}

.st-key-topnav .stButton > button p {
    font-family: var(--mono);
    font-size: 0.78rem;
}

.brand {
    display: flex;
    align-items: center;
    gap: 10px;
}

.logo {
    width: 30px;
    height: 30px;
    border-radius: 7px;
    background: rgba(70, 237, 224, 0.12);
    border: 1px solid rgba(70, 237, 224, 0.32);
    color: var(--accent-cyan);
    display: grid;
    place-items: center;
}

.brand-name {
    font-family: var(--display);
    color: var(--ink);
    font-size: 1.18rem;
    font-weight: 700;
    letter-spacing: -0.03em;
}

.brand-dot {
    color: var(--accent-cyan);
}

.nav-session {
    display: inline-flex;
    align-items: center;
    justify-content: flex-end;
    gap: 8px;
    padding: 5px 11px;
    border-radius: 6px;
    background: var(--surface);
    border: 1px solid var(--line-2);
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--muted);
    float: right;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.nav-session.active {
    color: var(--ink);
    border-color: var(--line);
}

.s-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex: none;
}

.s-dot.idle {
    background: var(--medium);
    animation: statusPulse 2.4s ease-in-out infinite;
}

.s-dot.ok {
    background: var(--accent);
}

.s-file {
    overflow: hidden;
    text-overflow: ellipsis;
}

.s-time {
    color: var(--muted);
}

/* ---------- hero ---------- */

.hero {
    text-align: center;
    padding: 36px 0 34px;
}

.hero-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 5px 12px;
    border-radius: 999px;
    background: var(--surface);
    border: 1px solid rgba(70, 237, 224, 0.28);
    font-family: var(--mono);
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    color: var(--accent-cyan);
    margin-bottom: 18px;
}

.pulse-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent-cyan);
    animation: statusPulse 2.2s ease-in-out infinite;
}

.pill-ver {
    color: var(--muted);
    font-weight: 500;
    padding-left: 6px;
    border-left: 1px solid var(--line);
}

.stApp .hero h1 {
    font-family: var(--display);
    color: var(--ink);
    font-size: clamp(2.25rem, 4.8vw, 3.35rem);
    line-height: 1.08;
    letter-spacing: -0.035em;
    font-weight: 700;
}

.hero .grad {
    color: #9FB8C7;
}

.stApp .hero-sub {
    color: var(--muted);
    font-size: 0.98rem;
    line-height: 1.65;
    max-width: 640px;
    margin: 14px auto 0;
    font-weight: 400;
}

.hero-telemetry {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 20px;
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--ink-2);
}

.hero-telemetry > span:not(.sep) {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 6px;
    background: var(--surface);
    border: 1px solid var(--line-2);
}

.hero-telemetry i {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent);
}

.hero-telemetry .sep {
    color: var(--line);
}

/* ---------- upload cards (subtle Z-axis lift on hover, no neon glow) ---------- */

[class*="st-key-card_"] {
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: var(--radius);
    padding: 22px 24px 20px !important;
    gap: 0.75rem;
    transition: transform 0.18s ease, border-color 0.18s ease, background 0.18s ease;
}

[class*="st-key-card_"]:hover {
    transform: translateY(-2px);
    border-color: var(--line);
    background: var(--surface-low);
}

.step-top {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 10px;
}

.step-n {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 8px;
    border-radius: 5px;
    font-family: var(--mono);
    font-size: 0.66rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    background: var(--raised);
    border: 1px solid var(--line-2);
    color: var(--accent-cyan);
}

.stApp .step h3 {
    font-family: var(--display);
    font-size: 1.2rem;
    letter-spacing: -0.02em;
    font-weight: 600;
    color: var(--ink);
}

.stApp .step p {
    color: var(--muted);
    margin-top: 6px;
    line-height: 1.55;
    font-size: 0.88rem;
}

.fmt {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 12px;
}

.fmt span {
    font-family: var(--mono);
    font-size: 0.68rem;
    background: var(--raised);
    border: 1px solid var(--line-2);
    color: var(--ink-2);
    padding: 3px 8px;
    border-radius: 5px;
}

[data-testid="stFileUploaderDropzone"] {
    background: #0D1111;
    border: 1.5px dashed var(--line);
    border-radius: var(--radius-sm);
    padding: 10px;
    margin-top:15px;
    transition: border-color 0.18s ease, background 0.18s ease;
}

[data-testid="stFileUploaderDropzone"]:hover {
    border-color: var(--accent);
    background: #101616;
}

[data-testid="stFileUploaderDropzone"] button {
    background: var(--raised);
    color: var(--ink);
    border: 1px solid var(--line);
}

[data-testid="stFileUploaderFile"] {
    background: var(--raised);
    border-radius: 6px;
    border: 1px solid var(--line);
}

.ready {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 9px;
    margin: 20px auto 14px;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 0.78rem;
    text-align: center;
}

.ready i {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--medium);
    display: inline-block;
    flex: none;
}

.ready.ok i {
    background: var(--accent);
}

.ready b {
    color: var(--ink);
    font-weight: 600;
}

/* ---------- feature section ---------- */

.features {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    margin: 40px 0 8px;
}

.feat {
    text-align: left;
    padding: 20px;
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: var(--radius);
    transition: transform 0.18s ease, border-color 0.18s ease;
}

.feat:hover {
    transform: translateY(-2px);
    border-color: var(--line);
}

.feat-ic {
    width: 38px;
    height: 38px;
    border-radius: 8px;
    background: var(--raised);
    border: 1px solid var(--line-2);
    display: grid;
    place-items: center;
    margin-bottom: 12px;
    color: var(--accent-cyan);
}

.feat-tag {
    font-family: var(--mono);
    font-size: 0.64rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    color: var(--accent-cyan);
    margin-bottom: 4px;
}

.stApp .feat h4 {
    font-family: var(--display);
    color: var(--ink);
    font-size: 1rem;
    font-weight: 600;
}

.stApp .feat p {
    color: var(--muted);
    font-size: 0.84rem;
    line-height: 1.55;
    margin-top: 6px;
}

[data-testid="stExpander"] {
    border: 1px solid var(--line-2) !important;
    background: var(--surface);
    border-radius: var(--radius);
}

[data-testid="stExpander"] summary {
    color: var(--ink);
    font-family: var(--display);
    font-weight: 600;
}

/* ---------- result header and verdict ---------- */

.res-head {
    padding: 12px 0 20px;
}

.eyebrow {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    color: var(--accent-cyan);
    font-family: var(--mono);
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    margin-bottom: 8px;
}

.eyebrow i {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent-cyan);
}

.stApp .res-head h1 {
    font-family: var(--mono);
    color: var(--ink);
    font-size: clamp(1.45rem, 3.4vw, 2rem);
    letter-spacing: -0.03em;
    font-weight: 700;
    word-break: break-all;
}

.res-meta {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin-top: 12px;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 0.74rem;
}

.vs {
    font-size: 0.76rem;
    color: var(--muted);
}

.pill {
    display: inline-block;
    padding: 4px 9px;
    border-radius: 6px;
    font-family: var(--mono);
    font-size: 0.72rem;
    font-weight: 500;
    background: var(--raised);
    color: var(--ink);
    border: 1px solid var(--line-2);
}

.pill.accent {
    background: var(--accent-50);
    color: var(--accent-cyan);
    border-color: rgba(70, 237, 224, 0.25);
}

.verdict {
    padding: 4px 0;
}

.verdict-top {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
}

.verdict-tag {
    font-family: var(--mono);
    font-size: 0.66rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    padding: 4px 9px;
    border-radius: 6px;
    white-space: nowrap;
}

.verdict-tag.crit {
    background: var(--high-bg);
    color: var(--high);
    border: 1px solid var(--high-line);
}

.verdict-tag.warn {
    background: var(--medium-bg);
    color: var(--medium);
    border: 1px solid var(--medium-line);
}

.verdict-tag.ok {
    background: var(--low-bg);
    color: var(--low);
    border: 1px solid var(--low-line);
}

.stApp .verdict h2 {
    font-family: var(--display);
    color: var(--ink);
    font-size: clamp(1.35rem, 3vw, 1.75rem);
    letter-spacing: -0.03em;
    font-weight: 700;
    line-height: 1.2;
}

.stApp .verdict p {
    color: var(--ink-2);
    font-size: 0.9rem;
    margin-top: 6px;
    line-height: 1.55;
}

.stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
    margin-top: 20px;
}

.stat-box {
    background: var(--surface-low);
    border: 1px solid var(--line-2);
    border-radius: var(--radius-sm);
    padding: 12px 14px;
}

.stat-n {
    font-family: var(--display);
    color: var(--ink);
    font-size: 1.95rem;
    font-weight: 700;
    letter-spacing: -0.04em;
    line-height: 1.1;
    margin-top: 6px;
}

.stat-l {
    display: flex;
    align-items: center;
    gap: 6px;
    font-family: var(--mono);
    color: var(--muted);
    font-size: 0.66rem;
    font-weight: 600;
    letter-spacing: 0.06em;
}

.stat-l i {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    display: inline-block;
}

.card-title {
    font-family: var(--display);
    color: var(--ink);
    font-size: 0.95rem;
    font-weight: 600;
    margin-bottom: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
}

.card-title small {
    font-family: var(--mono);
    color: var(--muted);
    font-weight: 500;
    font-size: 0.72rem;
}

.center {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
}

.ring {
    width: 142px;
    height: 142px;
}

.ring text.r-num {
    font-family: var(--display);
    font-size: 34px;
    font-weight: 700;
    fill: var(--ink);
    letter-spacing: -0.03em;
}

.ring text.r-lbl {
    font-family: var(--mono);
    font-size: 10px;
    fill: var(--muted);
}

.ring-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin-top: 8px;
    padding: 3px 10px;
    border-radius: 999px;
    font-family: var(--mono);
    font-size: 0.66rem;
    font-weight: 600;
    letter-spacing: 0.06em;
}

.ring-pill i {
    width: 6px;
    height: 6px;
    border-radius: 50%;
}

.ring-pill.low {
    background: var(--low-bg);
    color: var(--low);
    border: 1px solid var(--low-line);
}

.ring-pill.low i { background: var(--low); }

.ring-pill.med {
    background: var(--medium-bg);
    color: var(--medium);
    border: 1px solid var(--medium-line);
}

.ring-pill.med i { background: var(--medium); }

.ring-pill.high {
    background: var(--high-bg);
    color: var(--high);
    border: 1px solid var(--high-line);
}

.ring-pill.high i { background: var(--high); }

.stApp .formula {
    font-family: var(--mono);
    color: var(--muted);
    font-size: 0.7rem;
    margin-top: 10px;
}

.note {
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: var(--radius);
    padding: 14px 18px;
    color: var(--ink-2);
    font-size: 0.88rem;
    line-height: 1.55;
}

.note b {
    color: var(--ink);
}

.note code {
    background: var(--raised);
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.82em;
}

/* ---------- badges and chips ---------- */

.badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 9px;
    border-radius: 6px;
    font-family: var(--mono);
    font-size: 0.7rem;
    font-weight: 600;
    border: 1px solid transparent;
    white-space: nowrap;
}

.badge i {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    display: inline-block;
}

.badge.High {
    background: var(--high-bg);
    color: var(--high);
    border-color: var(--high-line);
}

.badge.High i {
    background: var(--high);
}

.badge.Medium {
    background: var(--medium-bg);
    color: var(--medium);
    border-color: var(--medium-line);
}

.badge.Medium i {
    background: var(--medium);
}

.badge.Low,
.badge.None {
    background: var(--low-bg);
    color: var(--low);
    border-color: var(--low-line);
}

.badge.Low i,
.badge.None i {
    background: var(--low);
}

.badge.t-modified {
    background: var(--t-modified-bg);
    color: var(--t-modified);
    border-color: rgba(70, 237, 224, 0.25);
}

.badge.t-added {
    background: var(--t-added-bg);
    color: var(--t-added);
    border-color: var(--low-line);
}

.badge.t-removed {
    background: var(--t-removed-bg);
    color: var(--t-removed);
    border-color: rgba(173, 198, 255, 0.25);
}

.badge.t-same {
    background: var(--raised);
    color: var(--muted);
}

.badge.s-Pending {
    background: var(--raised);
    color: var(--ink-2);
    border-color: var(--line-2);
}

.badge.s-Approved {
    background: var(--low-bg);
    color: var(--low);
    border-color: var(--low-line);
}

.badge.s-Rejected {
    background: var(--high-bg);
    color: var(--high);
    border-color: var(--high-line);
}

.chip {
    font-family: var(--mono);
    font-size: 0.75rem;
    padding: 3px 8px;
    border-radius: 5px;
    background: var(--raised);
    color: var(--ink-2);
    border: 1px solid var(--line-2);
    display: inline-block;
}

.chip.none {
    background: transparent;
    border: 1px dashed var(--line);
    color: var(--muted);
    font-style: italic;
}

.chip.t-modified {
    background: var(--t-modified-bg);
    color: var(--t-modified);
    border-color: rgba(70, 237, 224, 0.25);
}

.chip.t-added {
    background: var(--t-added-bg);
    color: var(--t-added);
    border-color: var(--low-line);
}

.chip.t-removed {
    background: var(--t-removed-bg);
    color: var(--t-removed);
    border-color: rgba(173, 198, 255, 0.25);
}

.tag {
    font-family: var(--mono);
    font-size: 0.64rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    padding: 2px 7px;
    border-radius: 4px;
    margin-left: 8px;
    vertical-align: 1px;
}

.tag-rule {
    background: var(--raised);
    color: var(--ink-2);
    border: 1px solid var(--line-2);
}

.tag-ai {
    background: var(--accent-50);
    color: var(--accent-cyan);
    border: 1px solid rgba(70, 237, 224, 0.25);
}

.key {
    display: block;
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--muted);
    margin-top: 3px;
}

.empty-state {
    text-align: center;
    padding: 56px 20px;
    color: var(--muted);
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: var(--radius);
}

.stApp .empty-state h3 {
    font-family: var(--display);
    color: var(--ink);
    font-size: 1.25rem;
    letter-spacing: -0.02em;
    margin-bottom: 6px;
}

.empty-state p {
    color: var(--muted);
    line-height: 1.6;
}

.empty-state .big {
    width: 54px;
    height: 54px;
    border-radius: 12px;
    background: var(--raised);
    border: 1px solid var(--line-2);
    color: var(--muted);
    display: grid;
    place-items: center;
    margin: 0 auto 14px;
}

.empty-state.ok .big {
    background: var(--low-bg);
    border-color: var(--low-line);
    color: var(--low);
}

.stApp .foot {
    margin-top: 44px;
    padding-top: 18px;
    border-top: 1px solid var(--line-2);
    color: var(--muted);
    font-family: var(--mono);
    font-size: 0.7rem;
}

.foot-inner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
}

.foot-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 6px;
    background: var(--surface);
    border: 1px solid var(--line-2);
    color: var(--ink-2);
}

.foot-badge i,
.foot-status i {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent);
    display: inline-block;
}

.foot-status {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--accent);
    font-weight: 600;
}

.mini-row {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin: 6px 0 16px;
}

.mini {
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: var(--radius-sm);
    padding: 12px 16px;
    display: flex;
    align-items: center;
    gap: 10px;
}

.mini b {
    font-family: var(--display);
    color: var(--ink);
    font-size: 1.2rem;
}

/* ---------- tables built from Streamlit columns ---------- */

[class*="st-key-tbl_"] {
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: var(--radius);
    overflow: hidden;
    gap: 0 !important;
    margin-top: 6px;
}

[class*="st-key-thead_"] {
    background: var(--surface-low);
    padding: 11px 18px;
}

.th {
    font-family: var(--mono);
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    font-weight: 600;
    white-space: nowrap;
}

[class*="st-key-trow_"] {
    border-top: 1px solid var(--line-2);
    padding: 12px 18px;
    transition: background 0.15s ease;
}

[class*="st-key-trow_"]:hover {
    background: rgba(255, 255, 255, 0.02);
}

[class*="st-key-trow_"] [data-testid="stVerticalBlock"] {
    gap: 0.15rem;
}

.table-wrap {
    overflow-x: auto;
    border: 1px solid var(--line-2);
    border-radius: var(--radius);
    background: var(--surface);
}

.table-wrap table {
    width: 100%;
    border-collapse: collapse;
}

.table-wrap th {
    text-align: left;
    font-family: var(--mono);
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    font-weight: 600;
    padding: 11px 16px;
    background: var(--surface-low);
}

.table-wrap td {
    color: var(--ink-2);
    padding: 11px 16px;
    border-top: 1px solid var(--line-2);
}

.table-wrap tr {
    transition: background 0.15s ease;
}

.table-wrap tbody tr:hover {
    background: rgba(255, 255, 255, 0.02);
}

.table-wrap .num {
    text-align: right;
}

/* ---------- code view ---------- */

.code {
    background: #0D1111;
    color: var(--ink-2);
    border: 1px solid var(--line-2);
    border-radius: var(--radius);
    padding: 14px 0;
    font-family: var(--mono);
    font-size: 0.78rem;
    overflow-x: auto;
}

.code .ln {
    display: block;
    padding: 2px 16px;
    white-space: pre;
    border-left: 3px solid transparent;
}

.code .ln.d-modified {
    background: rgba(70, 237, 224, 0.10);
    border-left-color: #46EDE0;
    color: var(--ink);
}

.code .ln.d-added {
    background: rgba(16, 185, 129, 0.11);
    border-left-color: #10B981;
    color: var(--ink);
}

.code .ln.d-removed {
    background: rgba(173, 198, 255, 0.11);
    border-left-color: #ADC6FF;
    color: var(--ink);
}

.code-title {
    font-family: var(--mono);
    font-size: 0.82rem;
    color: var(--ink);
    font-weight: 600;
    margin-bottom: 8px;
}

.stApp .hint {
    color: var(--muted);
    font-size: 0.78rem;
    margin-top: 8px;
}

/* ---------- buttons (flat architectural restraint, zero neon glow) ---------- */

.stButton > button,
.stDownloadButton > button {
    border-radius: 8px;
    font-family: var(--mono);
    font-size: 0.8rem;
    font-weight: 600;
    box-shadow: none !important;
    transition:
        background 0.15s ease,
        color 0.15s ease,
        border-color 0.15s ease,
        transform 0.12s ease;
}

.stButton > button:active,
.stDownloadButton > button:active {
    transform: translateY(1px);
}

.stButton > button[data-testid="stBaseButton-primary"] {
    background: var(--accent);
    border: 1px solid var(--accent);
    color: #061410;
    padding: 0.55rem 1.4rem;
}

.stButton > button[data-testid="stBaseButton-primary"]:hover {
    background: var(--accent-h);
    border-color: var(--accent-h);
    color: #04100C;
}

.stButton > button[data-testid="stBaseButton-primary"]:disabled {
    background: #1C2424;
    border-color: #253030;
    color: #5E6A6A;
}

.stButton > button[data-testid="stBaseButton-secondary"],
.stDownloadButton > button {
    background: var(--raised);
    border: 1px solid var(--line);
    color: var(--ink);
}

.stButton > button[data-testid="stBaseButton-secondary"]:hover,
.stDownloadButton > button:hover {
    border-color: var(--accent-cyan);
    color: var(--accent-cyan);
    background: var(--hover);
}

.stButton > button[data-testid="stBaseButton-tertiary"] {
    color: var(--accent-cyan);
    background: var(--surface);
    border: 1px solid var(--line-2);
}

.stButton > button[data-testid="stBaseButton-tertiary"]:hover {
    background: var(--raised);
    border-color: var(--line);
}

div[data-testid="stDialog"] .stButton > button {
    width: 100%;
}

[class*="st-key-rev_"] button {
    padding: 0.25rem 0.85rem;
    min-height: 0;
    font-size: 0.76rem;
    width: 100%;
}

/* ---------- inputs and select boxes ---------- */

.stApp input,
.stApp textarea,
.stApp [data-baseweb="select"] > div {
    background: var(--surface);
    color: var(--ink);
    border-color: var(--line);
    border-radius: 7px;
}

.stApp input:focus,
.stApp textarea:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 1px var(--accent);
}

.stApp [data-baseweb="popover"],
.stApp [data-baseweb="menu"] {
    background: var(--raised);
    border: 1px solid var(--line);
}

.stApp [role="option"] {
    color: var(--ink-2);
}

.stApp [role="option"]:hover {
    background: var(--hover);
}

.stApp [data-testid="stMetric"] {
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: var(--radius);
    padding: 14px 16px;
}

.stApp [data-testid="stMetricLabel"] {
    font-family: var(--mono);
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--muted);
}

.stApp [data-testid="stMetricValue"] {
    font-family: var(--display);
    color: var(--ink);
}

.stApp [data-testid="stAlert"] {
    border-radius: var(--radius-sm);
}

/* ---------- tabs (override Streamlit default red highlight with teal-cyan) ---------- */

.stApp [data-baseweb="tab-list"] {
    gap: 6px;
    border-bottom: 1px solid var(--line-2);
}

.stApp button[data-baseweb="tab"] {
    font-family: var(--display);
    font-weight: 600;
    color: var(--muted);
    background: transparent;
}

.stApp button[data-baseweb="tab"]:hover {
    color: var(--ink);
}

.stApp button[data-baseweb="tab"][aria-selected="true"] {
    color: var(--accent-cyan) !important;
}

.stApp [data-baseweb="tab-highlight"] {
    background-color: var(--accent-cyan) !important;
}

.stApp [data-testid="stDivider"] {
    border-color: var(--line-2);
}

/* ---------- review drawer ---------- */

div[data-testid="stDialog"] > div {
    position: fixed !important;
    inset: 0 !important;
    width: 100vw !important;
    max-width: none !important;
    height: 100vh !important;
    margin: 0 !important;
    padding: 0 !important;
    background: rgba(0, 0, 0, 0.72) !important;
    border-radius: 0 !important;
    align-items: stretch !important;
    justify-content: flex-end !important;
    backdrop-filter: blur(3px);
}

div[data-testid="stDialog"] section[role="dialog"] {
    width: min(560px, 100vw) !important;
    max-width: 560px !important;
    height: 100vh !important;
    max-height: 100vh !important;
    margin: 0 0 0 auto !important;
    border-radius: 0 !important;
    background: #0F1314 !important;
    border-left: 1px solid var(--line);
    box-shadow: -20px 0 50px rgba(0, 0, 0, 0.45);
    overflow-y: auto;
}

.drawer-head {
    padding: 0 0 14px;
    border-bottom: 1px solid var(--line-2);
    margin-bottom: 16px;
}

.stApp .drawer-head .eyebrow {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--muted);
    font-weight: 500;
}

.stApp .drawer-head h2 {
    font-family: var(--display);
    color: var(--ink);
    font-size: 1.45rem;
    letter-spacing: -0.025em;
    margin: 2px 0;
    padding: 0;
}

.drawer-head code {
    font-size: 0.78rem;
    color: var(--muted);
}

.badges {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 18px;
}

.sec {
    font-family: var(--mono);
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.09em;
    color: var(--muted);
    font-weight: 600;
    margin: 18px 0 10px;
}

.evidence {
    display: grid;
    grid-template-columns: 1fr auto 1fr;
    gap: 12px;
    align-items: center;
}

.evidence .box {
    border: 1px solid var(--line-2);
    border-radius: var(--radius-sm);
    padding: 12px 14px;
    background: var(--surface);
    min-width: 0;
    overflow-wrap: anywhere;
}

.evidence .box .lbl {
    font-family: var(--mono);
    font-size: 0.68rem;
    color: var(--muted);
    font-weight: 600;
    margin-bottom: 6px;
}

.arr {
    color: var(--muted);
    font-size: 1.15rem;
}

.exp-block {
    margin-bottom: 14px;
}

.stApp .exp-block h4 {
    font-family: var(--display);
    font-size: 0.88rem;
    font-weight: 600;
    margin-bottom: 5px;
    color: var(--ink);
}

.stApp .exp-block p {
    color: var(--ink-2);
    font-size: 0.88rem;
    line-height: 1.6;
}

.exp-block code,
.

"""