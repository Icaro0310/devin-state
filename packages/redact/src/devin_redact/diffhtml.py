"""Self-contained HTML before/after report — the ``devin-redact diff``
emitter.

Same secrecy contract as the JSON report and the SARIF emitter: the
report **never** carries matched secret text. The *before* column shows
the engine's lossy masked preview (``first4...last4``, stars for short
values); the *after* column is the ``<REDACTED:sha256prefix>`` tag that
``redact`` would write — the fingerprint is the tag's own content, so no
secret material is needed to render it. Every dynamic value is
HTML-escaped, so the report is safe to share for human review of
sensitive exports.

When the caller also supplies a dry-run ``redact()`` result, each row is
marked *planned* (an edit exists for that file/cell) or *detection-only*
— cross-chunk findings, secrets split across payload boundaries, are the
latter: per-cell rewriting cannot see them, so they need manual review.
"""

from __future__ import annotations

import html
import re

from . import __version__
from .engine import _BLOCKING_CATEGORIES

_TAG_PREFIX = "<REDACTED:"
_TEXT_LOC_PREFIX = "text:"
_LINE_SUFFIX_RE = re.compile(r":line \d+$")

_CSS = """\
:root{color-scheme:light dark}
body{font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;padding:2rem;background:#f6f7f9;color:#1c1e21}
main{max-width:1100px;margin:0 auto}
h1{font-size:1.4rem;margin:0 0 .25rem}
.meta{color:#5c6370;font-size:.85rem;margin:.15rem 0}
.cards{display:flex;flex-wrap:wrap;gap:.6rem;margin:1.1rem 0}
.card{background:#fff;border:1px solid #d8dbe0;border-radius:8px;padding:.55rem .9rem;min-width:6.5rem}
.card .num{display:block;font-size:1.35rem;font-weight:650}
.card .lbl{font-size:.75rem;color:#5c6370;text-transform:uppercase;letter-spacing:.03em}
table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #d8dbe0;border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:.45rem .7rem;border-bottom:1px solid #e5e7eb;font-size:.85rem;vertical-align:top}
th{background:#eef0f3;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;color:#444}
tr:last-child td{border-bottom:none}
tbody tr:nth-child(even){background:#fafbfc}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.8rem;word-break:break-all}
.badge{display:inline-block;padding:.08rem .5rem;border-radius:10px;font-size:.72rem;font-weight:600;white-space:nowrap}
.badge.secret{background:#fde8e8;color:#b91c1c}
.badge.pii{background:#e0ecfd;color:#1d4ed8}
.badge.planned{background:#e3f5e9;color:#18703c}
.badge.detonly{background:#fdf0d5;color:#92600a}
.badge.clean{background:#e3f5e9;color:#18703c}
.badge.review{background:#fdf0d5;color:#92600a}
.badge.blocked{background:#fde8e8;color:#b91c1c}
.before{color:#8a3b12}
.after{color:#18703c}
.sub{display:block;color:#5c6370;font-size:.72rem;margin-top:.15rem}
.empty{background:#fff;border:1px solid #d8dbe0;border-radius:8px;padding:1.2rem;color:#18703c}
section{margin:1.4rem 0}
section h2{font-size:1rem;margin:0 0 .5rem}
footer{color:#5c6370;font-size:.78rem;margin-top:2rem;line-height:1.5}
@media(prefers-color-scheme:dark){body{background:#14171a;color:#e2e4e9}.card,table,.empty{background:#1c2025;border-color:#333a42}th{background:#242a30;color:#aeb4bd}th,td{border-color:#2c323a}tbody tr:nth-child(even){background:#21262c}.meta,.sub,footer,.card .lbl{color:#8d949e}.badge.secret{background:#4a1d1d;color:#f2a3a3}.badge.pii{background:#1a2d4d;color:#9ec2f5}.badge.planned,.badge.clean{background:#153a24;color:#8fd6a8}.badge.detonly,.badge.review{background:#453212;color:#e8c37a}.badge.blocked{background:#4a1d1d;color:#f2a3a3}.before{color:#e8b08a}.after{color:#8fd6a8}.empty{color:#8fd6a8}}
"""


def _esc(value) -> str:
    """HTML-escape any report value (text and attribute positions)."""
    return html.escape(str(value), quote=True)


def _norm_location(location: str) -> str:
    """Reduce a finding ``location`` to the cell/line locator ``redact``
    edit entries use: ``text:line N`` → ``line N`` and
    ``table.col#rowid=N:line L`` → ``table.col#rowid=N``."""
    loc = str(location)
    loc = loc.removeprefix(_TEXT_LOC_PREFIX)
    return _LINE_SUFFIX_RE.sub("", loc)


def planned_locations(redact_result: dict) -> set[tuple[str, str]]:
    """``(file, location)`` pairs a dry-run ``redact()`` would rewrite.

    Pair with :func:`_norm_location` on finding locations — edit
    locations never carry the ``text:`` prefix or the ``:line`` suffix
    that scan findings add.
    """
    return {
        (str(e.get("file", "")), str(e.get("location", "")))
        for e in redact_result.get("edits", [])
    }


def _status_badge(status: str) -> str:
    cls = {"CLEAN": "clean", "REVIEW": "review", "BLOCKED": "blocked"}.get(
        status, "review"
    )
    return f'<span class="badge {cls}">{_esc(status)}</span>'


def _summary_cards(report: dict) -> str:
    cards = [
        ("files scanned", report.get("files_scanned", 0)),
        ("findings", report.get("findings_total", 0)),
        ("secret-class", report.get("secrets", 0)),
        ("emails", report.get("emails", 0)),
        ("abs. paths", report.get("absolute_paths", 0)),
        ("project names", report.get("project_names", 0)),
    ]
    body = "".join(
        f'<div class="card"><span class="num">{_esc(n)}</span>'
        f'<span class="lbl">{_esc(label)}</span></div>'
        for label, n in cards
    )
    return f'<div class="cards">{body}</div>'


def _category_cell(finding: dict) -> str:
    category = str(finding.get("category", ""))
    cls = "secret" if category in _BLOCKING_CATEGORIES else "pii"
    badge = f'<span class="badge {cls}">{_esc(category)}</span>'
    detail = " · ".join(
        p
        for p in (
            str(finding.get("pattern") or ""),
            str(finding.get("kind") or ""),
        )
        if p
    )
    if detail:
        badge += f'<span class="sub">{_esc(detail)}</span>'
    return badge


def _finding_row(index: int, finding: dict, planned: set[tuple[str, str]] | None) -> str:
    file = str(finding.get("file", ""))
    location = str(finding.get("location", ""))
    fingerprint = str(finding.get("fingerprint", ""))
    covered = (
        planned is not None
        and (file, _norm_location(location)) in planned
        and finding.get("kind") != "cross-chunk"
    )
    if planned is None or covered:
        after = f'<code class="after">{_esc(_TAG_PREFIX + fingerprint + ">")}</code>'
    else:
        after = '<code class="after muted">—</code>'
    if planned is None:
        plan_cell = '<span class="sub">—</span>'
    elif covered:
        plan_cell = '<span class="badge planned">planned</span>'
    else:
        plan_cell = '<span class="badge detonly">detection-only</span>'
    extra = []
    if finding.get("reason"):
        extra.append(f"reason: {finding['reason']}")
    if finding.get("target"):
        extra.append(f"target: {finding['target']}")
    before = f'<code class="before">{_esc(finding.get("preview", ""))}</code>'
    if extra:
        before += f'<span class="sub">{_esc("; ".join(extra))}</span>'
    return (
        "<tr>"
        f"<td>{index}</td>"
        f"<td><code>{_esc(file)}</code></td>"
        f"<td><code>{_esc(location)}</code></td>"
        f"<td>{_category_cell(finding)}</td>"
        f"<td>{before}</td>"
        f"<td>{after}</td>"
        f"<td><code>{_esc(fingerprint)}</code></td>"
        f"<td>{plan_cell}</td>"
        "</tr>"
    )


def _findings_section(report: dict, planned: set[tuple[str, str]] | None) -> str:
    findings = report.get("findings") or []
    if not findings:
        return (
            '<section class="findings"><h2>Findings</h2>'
            '<p class="empty">No findings — the scanned input matches no '
            "known secret or PII pattern. Nothing would be redacted.</p>"
            "</section>"
        )
    rows = "".join(
        _finding_row(i + 1, f, planned) for i, f in enumerate(findings)
    )
    head = "".join(
        f"<th>{h}</th>"
        for h in (
            "#",
            "File",
            "Location",
            "Category",
            "Before (masked)",
            "After",
            "Fingerprint",
            "Plan",
        )
    )
    return (
        '<section class="findings"><h2>Findings</h2>'
        f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>"
        "</section>"
    )


def _errors_section(report: dict) -> str:
    errors = report.get("errors") or []
    if not errors:
        return ""
    rows = "".join(
        f"<tr><td><code>{_esc(e.get('file', ''))}</code></td>"
        f"<td>{_esc(e.get('error', ''))}</td></tr>"
        for e in errors
    )
    return (
        '<section class="errors"><h2>Scan notes</h2>'
        "<table><thead><tr><th>File</th><th>Note</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></section>"
    )


def _categories_section(report: dict) -> str:
    by_category = report.get("by_category") or {}
    if not by_category:
        return ""
    chips = " ".join(
        f'<span class="badge {"secret" if c in _BLOCKING_CATEGORIES else "pii"}">'
        f"{_esc(c)} ×{_esc(n)}</span>"
        for c, n in sorted(by_category.items())
    )
    return f'<section class="categories"><h2>By category</h2><p>{chips}</p></section>'


def render_html(
    report: dict,
    *,
    targets: list[str] | None = None,
    planned: set[tuple[str, str]] | None = None,
) -> str:
    """Render a ``scan()`` report as a self-contained before/after HTML
    document (inline CSS, no external assets, deterministic).

    ``targets`` is the display list of scanned inputs; ``planned`` is the
    :func:`planned_locations` set from a dry-run ``redact()`` — when
    given, each row reports whether auto-redact covers it.
    """
    status = str(report.get("publication_status", ""))
    target_items = "".join(
        f"<li><code>{_esc(t)}</code></li>" for t in (targets or [])
    )
    target_html = (
        f'<ul class="meta">{target_items}</ul>' if target_items else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>devin-redact diff — before/after report</title>
<style>
{_CSS}
</style>
</head>
<body>
<main>
<header>
<h1>devin-redact diff <small>— before/after redaction report</small></h1>
<p class="meta">generated by devin-redact {_esc(__version__)} · read-only · publication status {_status_badge(status)}</p>
{target_html}
</header>
{_summary_cards(report)}
{_categories_section(report)}
{_findings_section(report, planned)}
{_errors_section(report)}
<footer>
<p>Secret values never appear in this report: <em>Before</em> is the
engine's lossy masked preview, <em>After</em> is the
<code>&lt;REDACTED:sha256prefix&gt;</code> tag that <code>redact</code>
writes. Rows marked <span class="badge detonly">detection-only</span> are
seen by the scanner but not covered by the automatic rewrite (for
example secrets split across chunk boundaries) — review them manually.
<code>env_assignment</code> replacements keep their <code>KEY=</code>
prefix; the tag replaces only the value.</p>
</footer>
</main>
</body>
</html>
"""
