#!/usr/bin/env python3
"""Sync container security-scan reports to Linear.

One issue per **vulnerability × image scope** (CVE-style ID plus Docker repo name, with `-slim` /
`-locked` / `-locked-wolfi` tag suffix rolled into the scope label so variants stay distinct).

Scanners are pluggable (see SCANNERS). **trivy** reads Trivy JSON; **trivy_grype** ingests
mixed Trivy + `grype` JSON (paths sniffed by document shape), merges by **(image ref, CVE id)**,
and syncs the combined findings (``_datahub_scanners`` on each record).

**Labels:** ``LINEAR_LABEL_IDS`` (optional) always applied on **new** issues. The script maps
affected image repo basenames to Acryl Linear component label ids (see
``_DEFAULT_LINEAR_REPO_LABEL_MAP``); on **updated** issues, repo labels are **merged** with existing
labels (nothing removed).

**Issue relations (new issues only):** after all creates, build an undirected graph: two new issues
share an edge if they have the same **CVE** (vulnerability id) or the same Trivy **PkgName** (if
set). In each **connected component** of that graph, add a **related** link for every pair of
issues (full clique). Linear has no multi-relation batch API; the script issues one
``issueRelationCreate`` per pair, ignoring benign duplicate-relation errors.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

LINEAR_GRAPHQL = "https://api.linear.app/graphql"

# Machine anchor legacy (old comments); new comments use markdown only — no HTML in Linear.
REFS_HTML_MARKER = "<!-- datahub-security-scan-refs -->"
# Heading for refs comments (markdown). Must stay findable via _comment_has_refs_anchor.
REFS_SECTION_HEADER = "### Git branch/tag scan history"
REFS_SECTION_INTRO = (
    "CI records each **branch** or **tag** where this finding was reported (UTC timestamps). "
    "Refs are deduplicated by name."
)
# Legacy headings (still recognized when parsing existing comments)
LEGACY_REFS_HEADERS = (
    "### DataHub Trivy: scans by git branch/tag",
    "### DataHub security scans: git branch/tag",
)
# Legacy HTML anchor (still recognized)
LEGACY_REFS_MARKER = "<!-- datahub-trivy-refs -->"

MAX_TITLE_LEN = 250

# Recognized Docker tag suffixes for Wolfi/registry variants (longest match first).
_VARIANT_TAG_SUFFIXES: tuple[str, ...] = ("locked-wolfi", "locked", "slim")

# Linear `IssueCreateInput.priority` (integer; see Linear API): 1 Urgent, 2 High, 3 Medium, 4 Low.
_LINEAR_PRIORITY_URGENT = 1
_LINEAR_PRIORITY_HIGH = 2


@dataclass(frozen=True)
class ScanRef:
    kind: str  # "branch" | "tag"
    name: str

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.name}"


# Trivy rows: (artifact_ref, result_target, class/type, vuln). artifact_ref = scanned image ref for scope.
GroupedRows = dict[str, list[tuple[str, str, str, dict[str, Any]]]]
ParserFn = Callable[[list[Path]], GroupedRows]


def _graphql(
    api_key: str, query: str, variables: dict[str, Any] | None = None
) -> dict[str, Any]:
    payload: dict[str, Any] = {"query": query}
    if variables is not None:
        payload["variables"] = variables
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        LINEAR_GRAPHQL,
        data=data,
        headers={
            "Authorization": api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode() if e.fp else ""
        raise RuntimeError(f"Linear HTTP {e.code}: {err_body}") from e
    if body.get("errors"):
        raise RuntimeError(f"Linear GraphQL errors: {body['errors']}")
    return body.get("data") or {}


def _split_image_ref(target: str) -> tuple[str, str]:
    """Best-effort parse of a Trivy `Target` into (repository basename, tag). Tag may be empty."""
    t = target.strip()
    if not t:
        return "", ""
    if "@sha256:" in t:
        t = t.split("@", 1)[0]
    if ":" in t:
        image_part, tag = t.rsplit(":", 1)
        repo = image_part.split("/")[-1]
        return repo, tag
    base = t.rstrip("/").split("/")[-1]
    return base, ""


def _variant_label_from_tag(tag: str) -> str:
    """Return the variant segment (e.g. slim, locked) or '' for the primary image tag."""
    if not tag:
        return ""
    lower = tag.lower()
    for suf in _VARIANT_TAG_SUFFIXES:
        suf_token = "-" + suf
        if lower.endswith(suf_token):
            return suf
    return ""


def _repo_scope_ticket_label(target: str) -> str:
    """Unique ticket scope: `datahub-executor` or `datahub-executor-slim` etc."""
    repo, tag = _split_image_ref(target)
    if not repo:
        return "unknown"
    variant = _variant_label_from_tag(tag)
    return f"{repo}-{variant}" if variant else repo


def _dedupe_preserve_order(ids: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in ids:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _unique_repo_basenames_from_occurrences(
    occurrences: list[tuple[str, str, str, dict[str, Any]]],
) -> list[str]:
    basenames: list[str] = []
    seen: set[str] = set()
    for artifact_ref, _, _, _ in occurrences:
        base, _tag = _split_image_ref(artifact_ref)
        b = (base or "").strip()
        if b and b not in seen:
            seen.add(b)
            basenames.append(b)
    return basenames


# Baked-in: image repo basename (e.g. datahub-gms) → Acryl Linear label id. Edit in code to add/change.
_DEFAULT_LINEAR_REPO_LABEL_MAP: dict[str, str] = {
    "datahub-actions": "75489fcb-ab53-4087-a764-cd699db9c32a",
    "datahub-executor": "976d804a-217c-421e-a34c-ab8d2c9748d5",
    "datahub-frontend-react": "f643839d-83c3-41a8-bb8e-c28ffb36a643",
    "datahub-gms": "b9f7f5f9-bfce-49bc-befd-089933bfc0d6",
    "datahub-integrations-service": "6c93348f-bf52-4ccb-a01b-7c461871ea57",
    "datahub-mae-consumer": "632fb146-90ea-4683-88b4-624f86f45f61",
    "datahub-mce-consumer": "5b8941e9-0df6-44e6-b4ab-bb8dece4a1e1",
    "datahub-upgrade": "4c4f0d98-4921-4f02-b432-6823c3fdbff7",
}


def _resolve_linear_repo_label_map() -> dict[str, str]:
    """Map image repo basename to Linear label id (copy of ``_DEFAULT_LINEAR_REPO_LABEL_MAP``)."""
    return dict(_DEFAULT_LINEAR_REPO_LABEL_MAP)


def _repo_label_ids_for_occurrences(
    repo_map: dict[str, str],
    occurrences: list[tuple[str, str, str, dict[str, Any]]],
) -> list[str]:
    if not repo_map:
        return []
    out: list[str] = []
    for name in _unique_repo_basenames_from_occurrences(occurrences):
        lid = repo_map.get(name)
        if lid:
            out.append(lid)
    return out


def _issue_graphql_label_ids(api_key: str, issue_id: str) -> list[str]:
    q = """
query IssueLabelIds($id: String!) {
  issue(id: $id) {
    labels { nodes { id } }
  }
}
"""
    data = _graphql(api_key, q, {"id": issue_id})
    issue = data.get("issue")
    if not issue:
        return []
    return [
        str(n["id"])
        for n in (issue.get("labels") or {}).get("nodes") or []
        if n.get("id")
    ]


def _issue_update_label_ids(api_key: str, issue_id: str, label_ids: list[str]) -> None:
    m = """
mutation IssueUpdateLabelIds($id: String!, $input: IssueUpdateInput!) {
  issueUpdate(id: $id, input: $input) {
    success
  }
}
"""
    u = _dedupe_preserve_order(label_ids)
    data = _graphql(
        api_key, m, {"id": issue_id, "input": {"labelIds": u}}
    )
    if not (data.get("issueUpdate") or {}).get("success"):
        raise RuntimeError(f"issueUpdate labelIds failed: {data}")


# Names that read poorly in GFM tables in Linear (long text, JSON blobs, URLs).
_TRIVY_STACK_WHEN_KEY: frozenset[str] = frozenset(
    {
        "Title",
        "PrimaryURL",
        "Description",
        "PkgPath",
        "VendorSeverity",
        "CVSS",
        "Layer",
        "DataSource",
        "PkgIdentifier",
        "Fingerprint",
        "VendorIDs",
        "VendorIds",
        "Commit",
        "FilePath",
        "CweIDs",
        "SecondaryURLs",
    }
)
# Long free text in nested advisory records (Trivy varies by key spelling).
_ADVISORY_LONG_TEXT_KEYS = frozenset({"Description", "Details", "Body"})

# Trivy fields in the **Technical details** section (see ``_trivy_technical_supporting_sections``).
_TECHNICAL_FOLD_KEYS: frozenset[str] = frozenset(
    {"CVSS", "Layer", "DataSource", "PkgIdentifier"}
)

# Strip before serializing to Linear (not vendor fields).
_INTERNAL_VULN_KEYS: frozenset[str] = frozenset(
    {"_datahub_scanners", "_datahub_scanner_source"}
)


def _plain_scalar_for_cell(val: Any) -> str:
    """Single-line plaintext for table cells."""
    if val is None:
        return ""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (dict, list)):
        compact = json.dumps(val, ensure_ascii=False, separators=(",", ":"))
        if len(compact) > 400:
            compact = compact[:397] + "..."
        return compact.replace("\n", " ")
    return str(val).strip().replace("\n", " ")


def _fmt_cell(val: Any) -> str:
    """Markdown pipe escaping (references section bullets)."""
    return _plain_scalar_for_cell(val).replace("|", "\\|")


def _markdown_table(header: tuple[str, str], rows: list[tuple[str, Any]]) -> str:
    """GFM pipe table — Linear renders these; column width is editor-controlled."""
    filtered = [(k, v) for k, v in rows if v is not None and v != ""]
    if not filtered:
        return ""
    lines = [
        f"| **{header[0]}** | **{header[1]}** |",
        "| :--- | :--- |",
    ]
    for key, val in filtered:
        lines.append(f"| {_fmt_cell(key)} | {_fmt_cell(val)} |")
    return "\n".join(lines) + "\n"


def _affected_result_target_class_table(detail_target: str, rclass: str) -> str:
    """One-row table: result target and class (Trivy ``Result`` target + type) side by side."""
    t = str(detail_target).strip() if detail_target is not None else ""
    c = str(rclass).strip() if rclass is not None else ""
    if not t and not c:
        return ""
    if not t:
        t = "—"
    if not c:
        c = "—"
    return _markdown_table(
        ("Result target", "Result class / type"),
        [(t, c)],
    )


def _trivy_technical_supporting_sections(technical: str, tail: str) -> str:
    """**Technical details** and **Supporting details** as separate Linear collapsible blocks.

    Linear makes sections toggleable with ``>>> `` (see editor docs) or ``/collapsible``; plain
    ``####`` headings are not collapsible. Two blocks are emitted as two top-level ``>>>`` sections
    (joined with a blank line) so each can expand/collapse on its own.
    """
    out: list[str] = []
    t = technical.strip() if technical else ""
    s = tail.strip() if tail else ""
    if t:
        out.append(">>> Technical details\n\n" + t + "\n")
    if s:
        out.append(">>> Supporting details\n\n" + s + "\n")
    if not out:
        return ""
    return "\n\n".join(out).rstrip() + "\n"


def _stacked_value_text(val: Any, *, max_len: int = 24_000) -> str:
    """Full text for stacked display; dict/list pretty-printed; strings keep newlines."""
    if isinstance(val, dict):
        raw = json.dumps(val, ensure_ascii=False, indent=2)
        return raw if len(raw) <= max_len else raw[: max_len - 3] + "..."
    if isinstance(val, list):
        raw = json.dumps(val, ensure_ascii=False, indent=2)
        return raw if len(raw) <= max_len else raw[: max_len - 3] + "..."
    if isinstance(val, bool):
        return "true" if val else "false"
    s = str(val).strip()
    return s if len(s) <= max_len else s[: max_len - 3] + "..."


def _should_stack_field_row(field_name: str, val: Any) -> bool:
    if isinstance(val, (dict, list)):
        return True
    if field_name in _TRIVY_STACK_WHEN_KEY or field_name in _ADVISORY_LONG_TEXT_KEYS:
        return True
    if isinstance(val, str) and len(val.strip()) > 100:
        return True
    return False


def _layout_field_rows_ordered(rows: list[tuple[str, Any]]) -> str:
    """Compact table for short fields; full-width stacked blocks for long / JSON / known-wide keys."""
    chunks: list[str] = []
    table_buf: list[tuple[str, Any]] = []

    def flush_table() -> None:
        if table_buf:
            chunks.append(_markdown_table(("Field", "Value"), table_buf))
            table_buf.clear()

    for key, val in rows:
        if val is None or val == "":
            continue
        if _should_stack_field_row(key, val):
            flush_table()
            chunks.append(_stacked_field_blocks([(key, val)]).rstrip())
        else:
            table_buf.append((key, val))
    flush_table()
    return ("\n\n".join(chunks).strip() + "\n") if chunks else ""


def _stacked_block_primary_url_if_applicable(label: Any, val: Any) -> str | None:
    """GFM link for Trivy PrimaryURL (not code — links are not clickable inside fences)."""
    if str(label) != "PrimaryURL":
        return None
    u = str(val).strip()
    if not (u.startswith("http://") or u.startswith("https://")):
        return None
    lbl = _plain_scalar_for_cell(label)
    # Link text = URL (Linear renders as one clickable line).
    return f"**{lbl}**\n\n[{u}]({u})"


def _stacked_field_blocks(rows: list[tuple[str, Any]]) -> str:
    """Full-width labels + values (avoids skinny GFM columns in Linear)."""
    blocks: list[str] = []
    for label, val in rows:
        if val is None or val == "":
            continue
        primary = _stacked_block_primary_url_if_applicable(label, val)
        if primary:
            blocks.append(primary)
            continue
        txt = _stacked_value_text(val)
        lbl = _plain_scalar_for_cell(label)
        use_fence = isinstance(val, (dict, list)) or "\n" in txt or len(txt) > 100
        if use_fence:
            blocks.append(f"**{lbl}**\n\n```\n{txt}\n```")
        else:
            blocks.append(f"**{lbl}**\n\n`{txt}`")
    return "\n\n".join(blocks) + ("\n" if blocks else "")


def _serialize_trivy_vulnerability_record(vuln: dict[str, Any]) -> tuple[str, str, str]:
    """Returns ``(main_body, supporting_tail, technical_fold_markdown)``.

    *technical* is CVSS/Layer/DataSource/PkgIdentifier. *supporting_tail* is references, extra
    key/values, and (first) **Timing & classification** — PublishedDate, LastModifiedDate, CweIDs,
    VendorSeverity — before ``### References`` and ``### Additional fields``.
    """
    chunks: list[str] = []

    identity_rows: list[tuple[str, Any]] = []
    pkg_rows: list[tuple[str, Any]] = []
    meta_rows: list[tuple[str, Any]] = []
    technical_fold: list[tuple[str, Any]] = []
    tech_extras: list[tuple[str, Any]] = []
    refs_links: list[str] = []

    inner = vuln.get("Vulnerability")
    inner_tbl: list[tuple[str, Any]] = []
    if isinstance(inner, dict):
        for k, v in sorted(inner.items()):
            if k == "References" and isinstance(v, list):
                refs_links.extend(str(x) for x in v if x)
            elif k == "Title":
                # Same text as the issue body H1 from _advisory_title_for_description.
                continue
            elif k == "Description":
                # Shown as plain text under the CVE / summary at the top of the body.
                continue
            else:
                inner_tbl.append((k, v))

    ordered = (
        "VulnerabilityID",
        "PkgName",
        "PkgPath",
        "InstalledVersion",
        "FixedVersion",
        "Severity",
        "Title",
        "PrimaryURL",
        "References",
        "PublishedDate",
        "LastModifiedDate",
        "CweIDs",
        "VendorSeverity",
        "CVSS",
        "Layer",
        "FilePath",
        "DataSource",
        "PkgIdentifier",
    )
    seen: set[str] = set()
    for k in ordered:
        if k not in vuln or k == "Vulnerability":
            continue
        seen.add(k)
        v = vuln[k]
        if k == "References":
            if isinstance(v, list):
                refs_links.extend(str(x) for x in v if x)
            continue
        if k == "Title":
            # Duplicates the description H1 (advisory full title).
            continue
        if k in ("VulnerabilityID", "Severity", "PrimaryURL"):
            identity_rows.append((k, v))
        elif k in ("PkgName", "PkgPath", "InstalledVersion", "FixedVersion"):
            pkg_rows.append((k, v))
        elif k in ("PublishedDate", "LastModifiedDate", "CweIDs", "VendorSeverity"):
            meta_rows.append((k, v))
        elif k in _TECHNICAL_FOLD_KEYS:
            technical_fold.append((k, v))
        elif k == "FilePath":
            tech_extras.append((k, v))
        else:
            tech_extras.append((k, v))

    rest = {
        k: v
        for k, v in vuln.items()
        if k != "Vulnerability"
        and k not in seen
        and k != "Description"
        and k not in _INTERNAL_VULN_KEYS
    }

    if identity_rows:
        chunks.append("#### Identity & severity\n\n")
        chunks.append(_layout_field_rows_ordered(identity_rows))
    if pkg_rows:
        chunks.append("#### Package\n\n")
        chunks.append(_layout_field_rows_ordered(pkg_rows))
    if inner_tbl:
        chunks.append("#### Advisory / vulnerability record\n\n")
        chunks.append(_layout_field_rows_ordered(inner_tbl))
    if tech_extras:
        chunks.append("#### Other details\n\n")
        chunks.append(_layout_field_rows_ordered(tech_extras))

    technical_fold_str = (
        _layout_field_rows_ordered(technical_fold).strip() if technical_fold else ""
    )

    dedup_refs = list(dict.fromkeys(refs_links))
    tail_parts: list[str] = []
    if meta_rows:
        tail_parts.append(
            "#### Timing & classification\n\n"
            + _layout_field_rows_ordered(meta_rows).rstrip()
        )
    if dedup_refs:
        bullets = "\n".join(
            f"- [{u}]({u})" if u.startswith("http") else f"- `{_fmt_cell(u)}`"
            for u in dedup_refs
        )
        tail_parts.append("### References\n\n" + bullets)
    if rest:
        rest_body = _layout_field_rows_ordered(sorted(rest.items())).rstrip()
        if dedup_refs or meta_rows:
            tail_parts.append("### Additional fields\n\n" + rest_body)
        else:
            tail_parts.append(rest_body)

    if not tail_parts:
        tail_out = ""
    elif len(tail_parts) == 1 and not meta_rows and not dedup_refs and rest:
        # Prior shape: a single "additional fields" block with one ### heading in Supporting.
        tail_out = f"### Additional fields\n\n{tail_parts[0]}"
    else:
        tail_out = "\n\n".join(tail_parts)

    main = "\n".join(chunks).strip()
    return main, tail_out, technical_fold_str


def _raw_finding_table(vuln: dict[str, Any]) -> str:
    rows = [
        (k, v)
        for k, v in sorted(vuln.items(), key=lambda kv: kv[0])
        if k != "Title"
    ]
    return _layout_field_rows_ordered(rows)


def _try_load_json_report(p: Path) -> dict[str, Any] | None:
    """Load a Trivy/Grype JSON report; skip empty or invalid files with a stderr warning."""
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        print(
            f"WARNING: {p.name}: could not read ({exc}); skipping",
            file=sys.stderr,
        )
        return None
    if not raw.strip():
        print(
            f"WARNING: {p.name}: empty report file; skipping",
            file=sys.stderr,
        )
        return None
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(
            f"WARNING: {p.name}: invalid JSON ({exc}); skipping",
            file=sys.stderr,
        )
        return None
    if not isinstance(doc, dict):
        print(
            f"WARNING: {p.name}: expected JSON object, got {type(doc).__name__}; skipping",
            file=sys.stderr,
        )
        return None
    return doc


def _load_json_files(paths: list[Path]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in paths:
        if not p.is_file():
            raise FileNotFoundError(p)
        doc = _try_load_json_report(p)
        if doc is not None:
            out.append(doc)
    return out


def _trivy_vulnerability_id(vuln: dict[str, Any]) -> str:
    vid = vuln.get("VulnerabilityID")
    if vid:
        return str(vid)
    inner = vuln.get("Vulnerability")
    if isinstance(inner, dict) and inner.get("VulnerabilityID"):
        return str(inner["VulnerabilityID"])
    return f"UNKNOWN:{vuln.get('PkgName', '')}:{vuln.get('Title', '')}"[:120]


def _trivy_severity_string(vuln: dict[str, Any]) -> str | None:
    """Trivy finding severity (top-level or nested under Vulnerability)."""
    s = vuln.get("Severity")
    if s:
        return str(s).strip()
    inner = vuln.get("Vulnerability")
    if isinstance(inner, dict) and inner.get("Severity"):
        return str(inner["Severity"]).strip()
    return None


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _worst_trivy_severity(
    occurrences: list[tuple[str, str, str, dict[str, Any]]],
) -> str | None:
    """Highest-severity label across occurrences (used for Linear priority)."""
    best_rank = -1
    label: str | None = None
    for _, _, _, vuln in occurrences:
        raw = _trivy_severity_string(vuln)
        if not raw:
            continue
        u = raw.upper()
        rnk = _SEVERITY_RANK.get(u, 0)
        if rnk > best_rank:
            best_rank = rnk
            label = u
    return label


def _linear_priority_for_scan_severity(severity_upper: str | None) -> int | None:
    """Map Trivy severities we surface in this workflow to Linear numeric priority."""
    if not severity_upper:
        return None
    s = severity_upper.strip().upper()
    if s == "CRITICAL":
        return _LINEAR_PRIORITY_URGENT
    if s == "HIGH":
        return _LINEAR_PRIORITY_HIGH
    return None


def _linear_due_date_for_scan_severity(severity_upper: str | None) -> str | None:
    """Linear ``IssueCreateInput.dueDate`` (``TimelessDate`` = ``YYYY-MM-DD``, UTC calendar)."""
    if not severity_upper:
        return None
    s = severity_upper.strip().upper()
    if s == "CRITICAL":
        days = 16
    elif s == "HIGH":
        days = 31
    else:
        return None
    day = datetime.now(timezone.utc).date() + timedelta(days=days)
    return day.isoformat()


def _iter_trivy_findings(
    reports: list[dict[str, Any]],
) -> list[tuple[str, str, str, dict[str, Any]]]:
    rows: list[tuple[str, str, str, dict[str, Any]]] = []
    for doc in reports:
        artifact = doc.get("ArtifactName") or doc.get("ArtifactType") or "unknown"
        for result in doc.get("Results") or []:
            detail_target = result.get("Target") or artifact
            rclass = result.get("Class") or ""
            rtype = result.get("Type") or ""
            for vuln in result.get("Vulnerabilities") or []:
                rows.append(
                    (artifact, detail_target, f"{rclass}/{rtype}".strip("/"), dict(vuln))
                )
    return rows


def parse_trivy_reports(paths: list[Path]) -> GroupedRows:
    """Parse Trivy JSON; group by vulnerability ID + repo/variant scope (Linear ticket identity)."""
    reports = _load_json_files(paths)
    rows = _iter_trivy_findings(reports)
    groups: GroupedRows = {}
    for artifact_ref, detail_target, rclass, vuln in rows:
        vid = _trivy_vulnerability_id(vuln)
        scope = _repo_scope_ticket_label(artifact_ref)
        gkey = f"{vid}\x1f{scope}"
        groups.setdefault(gkey, []).append((artifact_ref, detail_target, rclass, vuln))
    return groups


def _report_json_kind(doc: dict[str, Any]) -> str:
    """``trivy`` vs ``grype`` from top-level JSON shape."""
    if isinstance(doc.get("Results"), list):
        return "trivy"
    if isinstance(doc.get("matches"), list):
        return "grype"
    return "unknown"


def _grype_image_ref(doc: dict[str, Any]) -> str:
    src = doc.get("source") or {}
    t = src.get("target")
    if isinstance(t, dict):
        u = t.get("userInput") or t.get("fullTag") or t.get("imageID")
        if u:
            return str(u)
    if isinstance(t, str) and t.strip():
        return t.strip()
    return "unknown"


def _grype_severity_to_trivy_upper(v: dict[str, Any]) -> str:
    """Map Grype ``vulnerability.severity`` to Trivy-style ``HIGH`` / ``CRITICAL`` labels."""
    s = str(v.get("severity") or "").strip().upper()
    if s in ("MEDIUM", "MED", "M"):
        return "MEDIUM"
    if s in ("LOW", "L"):
        return "LOW"
    if s in ("NEGLIGIBLE", "NEGL", "INFO", "INFORMATIONAL"):
        return "UNKNOWN"
    return s


def _grype_match_to_trivy_vuln(match: dict[str, Any]) -> dict[str, Any]:
    """Shape a Grype match like a Trivy ``Vulnerabilities[]`` entry for shared layout code."""
    v = match.get("vulnerability") or {}
    art = match.get("artifact") or {}
    vid = str(v.get("id") or "").strip()
    sev = _grype_severity_to_trivy_upper(v)
    desc = v.get("description")
    urls = [str(x) for x in (v.get("urls") or []) if x]
    primary = urls[0] if urls else None
    inner: dict[str, Any] = {}
    if vid:
        inner["VulnerabilityID"] = vid
        inner["Title"] = vid
    if desc is not None and str(desc).strip():
        inner["Description"] = str(desc).strip()
    if primary:
        inner["PrimaryURL"] = primary
    out: dict[str, Any] = {
        "VulnerabilityID": vid,
        "Title": vid,
        "PkgName": str(art.get("name") or ""),
        "InstalledVersion": str(art.get("version") or ""),
        "Severity": sev,
        "PrimaryURL": primary,
        "References": urls,
        "Vulnerability": inner,
        "DataSource": v.get("dataSource"),
        "_datahub_scanner_source": "grype",
    }
    locs = art.get("locations") or []
    if locs and isinstance(locs[0], dict) and locs[0].get("path"):
        out["FilePath"] = str(locs[0]["path"])
    if v.get("cvss") is not None:
        out["CVSS"] = v.get("cvss")
    fix = v.get("fix")
    if isinstance(fix, dict) and fix.get("versions"):
        out["FixedVersion"] = ", ".join(str(x) for x in fix.get("versions") or [])
    return out


# Match CI: Trivy uses only HIGH and CRITICAL in the security workflow.
_GRYPE_SEVERITY_ALLOWLIST: frozenset[str] = frozenset({"HIGH", "CRITICAL"})


def _iter_grype_findings(doc: dict[str, Any]) -> list[tuple[str, str, str, dict[str, Any]]]:
    rows: list[tuple[str, str, str, dict[str, Any]]] = []
    art_ref = _grype_image_ref(doc)
    for m in doc.get("matches") or []:
        vg = m.get("vulnerability") or {}
        sev = _grype_severity_to_trivy_upper(vg)
        if sev not in _GRYPE_SEVERITY_ALLOWLIST:
            continue
        vuln = _grype_match_to_trivy_vuln(m)
        gart = m.get("artifact") or {}
        rclass = f"grype/{str(gart.get('type') or 'package')}"
        rows.append((art_ref, art_ref, rclass, vuln))
    return rows


def _merge_trivy_grype_rows_for_same_image_cve(
    rows: list[tuple[str, str, str, dict[str, Any]]],
) -> list[tuple[str, str, str, dict[str, Any]]]:
    """One row per (scanned image ref, CVE) with ``_datahub_scanners``; prefer Trivy record when both exist."""
    buckets: dict[tuple[str, str], list[tuple[str, str, str, dict[str, Any]]]] = defaultdict(list)
    for row in rows:
        artifact, _target, _rclass, vuln = row
        vid = _trivy_vulnerability_id(vuln)
        buckets[(artifact, vid)].append(row)
    out: list[tuple[str, str, str, dict[str, Any]]] = []
    for _k, group in buckets.items():
        trivy: tuple[str, str, str, dict[str, Any]] | None = None
        grype: tuple[str, str, str, dict[str, Any]] | None = None
        for artifact, target, rclass, vuln in group:
            src = vuln.get("_datahub_scanner_source", "")
            if src == "trivy":
                trivy = (artifact, target, rclass, vuln)
            elif src == "grype":
                grype = (artifact, target, rclass, vuln)
        if trivy and grype:
            a, t, c, v = trivy
            v2 = dict(v)
            v2.pop("_datahub_scanner_source", None)
            v2["_datahub_scanners"] = ["trivy", "grype"]
            out.append((a, t, c, v2))
        elif trivy:
            a, t, c, v = trivy
            v2 = dict(v)
            v2.pop("_datahub_scanner_source", None)
            v2["_datahub_scanners"] = ["trivy"]
            out.append((a, t, c, v2))
        elif grype:
            a, t, c, v = grype
            v2 = dict(v)
            v2.pop("_datahub_scanner_source", None)
            v2["_datahub_scanners"] = ["grype"]
            out.append((a, t, c, v2))
        else:
            artifact, target, rclass, vuln = group[0]
            v2 = dict(vuln)
            v2.pop("_datahub_scanner_source", None)
            v2["_datahub_scanners"] = ["unknown"]
            out.append((artifact, target, rclass, v2))
    return out


def parse_trivy_grype_merged(paths: list[Path]) -> GroupedRows:
    """Load Trivy and/or Grype JSON (auto-detect per file), merge by image + CVE, then group for Linear."""
    all_rows: list[tuple[str, str, str, dict[str, Any]]] = []
    for p in paths:
        if not p.is_file():
            continue
        doc = _try_load_json_report(p)
        if doc is None:
            continue
        kind = _report_json_kind(doc)
        if kind == "trivy":
            for a, t, c, v in _iter_trivy_findings([doc]):
                vv = dict(v)
                vv["_datahub_scanner_source"] = "trivy"
                all_rows.append((a, t, c, vv))
        elif kind == "grype":
            all_rows.extend(_iter_grype_findings(doc))
        else:
            print(
                f"WARNING: {p.name}: not Trivy (Results) or Grype (matches) JSON; skipping",
                file=sys.stderr,
            )
    if not all_rows:
        return {}
    merged = _merge_trivy_grype_rows_for_same_image_cve(all_rows)
    groups: GroupedRows = {}
    for artifact_ref, detail_target, rclass, vuln in merged:
        vid = _trivy_vulnerability_id(vuln)
        scope = _repo_scope_ticket_label(artifact_ref)
        gkey = f"{vid}\x1f{scope}"
        groups.setdefault(gkey, []).append((artifact_ref, detail_target, rclass, vuln))
    return groups


SCANNERS: dict[str, ParserFn] = {
    "trivy": parse_trivy_reports,
    "trivy_grype": parse_trivy_grype_merged,
}


def _trivy_pkg_name_for_title(vuln: dict[str, Any]) -> str:
    """Installed package identifier for short issue titles (not CVE advisory prose)."""
    raw = ""
    pn = vuln.get("PkgName")
    if pn:
        raw = str(pn).strip()
    elif isinstance(vuln.get("PkgPath"), str) and vuln["PkgPath"].strip():
        raw = vuln["PkgPath"].strip().split("/")[-1]
    else:
        inner = vuln.get("Vulnerability")
        if isinstance(inner, dict) and inner.get("PkgName"):
            raw = str(inner["PkgName"]).strip()
    if not raw:
        return ""
    # Trivy adds ecosystem markers like "urllib3 (Python)"; strip trailing " (…)" for titles.
    return re.sub(r" \([^)]+\)$", "", raw).strip() or raw


def _linear_issue_title(
    vid: str,
    first_vuln: dict[str, Any],
    repo_scope_label: str,
    *,
    scanner: str,
) -> str:
    """`CVE-…: {package} (datahub-executor-slim)` for Trivy; scope is the unique image/variant id."""
    if scanner in ("trivy", "trivy_grype"):
        mid = _trivy_pkg_name_for_title(first_vuln).strip()
    else:
        ttitle = first_vuln.get("Title") or ""
        inner = first_vuln.get("Vulnerability")
        if isinstance(inner, dict) and inner.get("Title"):
            ttitle = str(inner["Title"])
        mid = (ttitle or "").strip()
    if not mid:
        mid = vid.strip()
    suffix = f" ({repo_scope_label})"
    max_inner = max(0, MAX_TITLE_LEN - len(suffix))
    inner_line = f"{vid}: {mid}"
    if len(inner_line) <= max_inner:
        return (inner_line + suffix)[:MAX_TITLE_LEN]
    prefix = f"{vid}: "
    budget = max_inner - len(prefix)
    if budget < 12:
        return (vid + suffix)[:MAX_TITLE_LEN]
    truncated = f"{prefix}{mid[: budget - 3]}..." + suffix
    return truncated[:MAX_TITLE_LEN]


def _advisory_title_for_description(
    scanner: str, first_vuln: dict[str, Any], fallback: str
) -> str:
    """Full vulnerability/advisory title from the report (H1 in issue body). Not the short Linear issue title."""
    ttitle = first_vuln.get("Title") or ""
    inner = first_vuln.get("Vulnerability")
    if isinstance(inner, dict) and inner.get("Title"):
        ttitle = str(inner["Title"])
    t = (ttitle or "").strip()
    return t if t else fallback


def _scanner_cell_from_occurrences(
    occurrences: list[tuple[str, str, str, dict[str, Any]]],
    fallback_label: str,
) -> str:
    """Table cell for **Scanner** — merged tool names from ``_datahub_scanners`` when present."""
    seen: set[str] = set()
    for *_, v in occurrences:
        for s in v.get("_datahub_scanners") or []:
            if s:
                seen.add(str(s).strip().lower())
    if seen:
        return "`" + ", ".join(sorted(seen)) + "`"
    return f"`{fallback_label}`"


def _trivy_advisory_description_plain(vuln: dict[str, Any]) -> str:
    """Advisory body text for the top of the issue (not code-fenced; same as nested ``Vulnerability.Description``)."""
    inner = vuln.get("Vulnerability")
    if isinstance(inner, dict) and inner.get("Description") is not None:
        t = str(inner["Description"]).strip()
        if t:
            return t
    d = vuln.get("Description")
    if d is not None and str(d).strip():
        return str(d).strip()
    return ""


def _build_description(
    scanner: str,
    vid: str,
    occurrences: list[tuple[str, str, str, dict[str, Any]]],
    run_url: str,
    scan_ref: ScanRef,
    commit_sha: str,
    description_heading: str,
    repo_scope_label: str,
) -> str:
    parts: list[str] = []
    parts.append(f"# {description_heading}\n")
    summary_rows: list[tuple[str, Any]] = [
        ("Vulnerability ID", f"`{vid}`"),
        ("Image scope (ticket id)", f"`{repo_scope_label}`"),
        ("Scanner", _scanner_cell_from_occurrences(occurrences, scanner)),
    ]
    parts.append(_markdown_table(("Property", "Value"), summary_rows))
    if scanner in ("trivy", "trivy_grype") and occurrences:
        desc_top = _trivy_advisory_description_plain(occurrences[0][3])
        if desc_top:
            parts.append("\n" + desc_top + "\n\n")

    seen: set[str] = set()
    occ_idx = 0
    occ_blocks: list[str] = []
    for artifact_ref, detail_target, rclass, vuln in occurrences:
        dedupe = f"{artifact_ref}\x1f{detail_target}"
        if dedupe in seen:
            continue
        seen.add(dedupe)
        occ_idx += 1
        stacked = _stacked_field_blocks([("Scanned artifact", artifact_ref)])
        result_table = _affected_result_target_class_table(detail_target, rclass)
        occ_top = stacked.rstrip() + (f"\n\n{result_table}" if result_table else "")
        occ_body: list[str] = [
            f"### Affected image #{occ_idx}\n",
            occ_top,
        ]
        if scanner in ("trivy", "trivy_grype"):
            main, tail, technical = _serialize_trivy_vulnerability_record(vuln)
            occ_body.append(main)
            ts = _trivy_technical_supporting_sections(technical, tail)
            if ts:
                occ_body.append(ts)
        else:
            occ_body.append("#### Raw finding\n\n")
            occ_body.append(_raw_finding_table(vuln))
        occ_blocks.append("\n".join(occ_body).strip())

    parts.append("\n\n---\n\n".join(occ_blocks))

    run_cell = f"[View workflow run]({run_url})" if run_url else "—"
    meta_inner = _markdown_table(
        ("Property", "Value"),
        [
            ("Git ref", f"`{scan_ref.key}`"),
            ("Commit", f"`{commit_sha}`"),
            ("Workflow run", run_cell),
        ],
    )
    # Scan / workflow line — keep after occurrence blocks; Technical/Supporting use Linear ``>>>`` there.
    scan_section = f"### Scan metadata\n\n{meta_inner.rstrip()}"
    parts.append("\n\n" + scan_section)
    return "\n".join(parts).strip()


def _parse_existing_ref_keys(comment_body: str) -> dict[str, str]:
    """Collect ref bullet lines anywhere in the comment (legacy or wrapped in <details>)."""
    keys: dict[str, str] = {}
    for line in comment_body.splitlines():
        line = line.strip()
        m = re.match(r"^[-*]\s*`(branch|tag):([^`]+)`", line)
        if m:
            k = f"{m.group(1)}:{m.group(2)}"
            keys[k] = line
    return keys


def _format_ref_line(
    scan_ref: ScanRef, short_sha: str, run_url: str, utc_now: str
) -> str:
    return (
        f"- `{scan_ref.key}` — SHA `{short_sha}` — "
        f"[workflow run]({run_url}) — {utc_now}"
    )


def _format_refs_comment_body(keys: dict[str, str]) -> str:
    lines = sorted(keys.values(), key=lambda s: s.lower())
    # Plain markdown only — Linear displays raw `<details>` / HTML comments as text.
    return (
        f"{REFS_SECTION_HEADER}\n\n"
        f"{REFS_SECTION_INTRO}\n\n"
        + "\n".join(lines)
        + "\n"
    )


def _merge_refs_comment(
    previous_body: str | None,
    scan_ref: ScanRef,
    short_sha: str,
    run_url: str,
) -> str:
    utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_line = _format_ref_line(scan_ref, short_sha, run_url, utc_now)
    keys: dict[str, str] = {}
    if previous_body:
        keys = _parse_existing_ref_keys(previous_body)
    if scan_ref.key in keys:
        return _format_refs_comment_body(keys)
    keys[scan_ref.key] = new_line
    return _format_refs_comment_body(keys)


def _find_issue_by_title(api_key: str, team_id: str, title: str) -> str | None:
    q = """
query IssuesByTitle($teamId: ID!, $title: String!) {
  issues(
    filter: { team: { id: { eq: $teamId } }, title: { eq: $title } }
    first: 5
  ) {
    nodes { id identifier title }
  }
}
"""
    data = _graphql(
        api_key,
        q,
        {"teamId": team_id, "title": title},
    )
    nodes = (data.get("issues") or {}).get("nodes") or []
    if not nodes:
        return None
    return str(nodes[0]["id"])


def _resolve_issue_create_state_id(api_key: str, team_id: str) -> str | None:
    """Workflow state UUID for issueCreate (`stateId`).

    Priority:
    1. ``LINEAR_ISSUE_STATE_ID`` — explicit UUID (always wins).
    2. Else, if the team has **triage enabled**, use ``Team.triageIssueState`` — the state Linear
       uses for issues opened by integrations/non-members when triage is on (often named *Triage*).
    3. Otherwise omit ``stateId`` and Linear applies the team's normal default for API creates.

    Workspace states are UUIDs; ``LINEAR_ISSUE_STATE_ID`` overrides when auto triage is wrong.
    """
    explicit = os.environ.get("LINEAR_ISSUE_STATE_ID", "").strip()
    if explicit:
        return explicit
    q = """
query TeamTriageIssueState($id: String!) {
  team(id: $id) {
    triageEnabled
    triageIssueState {
      id
      name
    }
  }
}
"""
    data = _graphql(api_key, q, {"id": team_id})
    team = data.get("team") or {}
    if not team.get("triageEnabled"):
        return None
    triage_st = team.get("triageIssueState") or {}
    tid = triage_st.get("id")
    return str(tid) if tid else None


def _create_issue(
    api_key: str,
    team_id: str,
    title: str,
    description: str,
    label_ids: list[str] | None,
    priority: int | None,
    state_id: str | None,
    due_date: str | None,
) -> str:
    m = """
mutation CreateIssue($input: IssueCreateInput!) {
  issueCreate(input: $input) {
    success
    issue { id identifier url }
  }
}
"""
    input_payload: dict[str, Any] = {
        "teamId": team_id,
        "title": title,
        "description": description,
    }
    if label_ids:
        input_payload["labelIds"] = label_ids
    if priority is not None:
        input_payload["priority"] = priority
    if state_id:
        input_payload["stateId"] = state_id
    if due_date:
        input_payload["dueDate"] = due_date
    data = _graphql(api_key, m, {"input": input_payload})
    result = data.get("issueCreate") or {}
    if not result.get("success"):
        raise RuntimeError(f"issueCreate failed: {data}")
    issue = result.get("issue") or {}
    return str(issue["id"])


def _link_issue_related(
    api_key: str, issue_id: str, related_issue_id: str
) -> None:
    """Create a ``related`` link between two issues (Linear is symmetric; one call per pair)."""
    m = """
mutation IssueRelationCreate($input: IssueRelationCreateInput!) {
  issueRelationCreate(input: $input) {
    success
    issueRelation { id type }
  }
}
"""
    data = _graphql(
        api_key,
        m,
        {
            "input": {
                "issueId": issue_id,
                "relatedIssueId": related_issue_id,
                "type": "related",
            }
        },
    )
    result = data.get("issueRelationCreate") or {}
    if not result.get("success"):
        raise RuntimeError(f"issueRelationCreate failed: {data}")


def _link_issue_related_best_effort(
    api_key: str, issue_id: str, related_issue_id: str
) -> str:
    """Try ``_link_issue_related``; return a non-empty message only on a non-duplicate error."""
    try:
        _link_issue_related(api_key, issue_id, related_issue_id)
    except RuntimeError as e:
        em = str(e).lower()
        if any(
            x in em
            for x in (
                "existing",
                "already",
                "duplicate",
                " unique",
                "constraint",
            )
        ):
            return ""
        return str(e)
    return ""


def _undirected_pair_key(a: str, b: str) -> tuple[str, str]:
    return (a, b) if a < b else (b, a)


def _issue_pairs_cve_or_pkg(
    created: list[tuple[str, str, str]],
) -> set[tuple[str, str]]:
    """Pairs of new issue ids that must be *related* (clique on each OR-connected component).

    ``created`` entries: ``(issue_id, vid, pkg_key)``. Edge between i and j if ``vid`` matches, or
    (for non-empty package keys) ``pkg_key`` matches — then union-find, then all pairs per component.
    """
    n = len(created)
    if n < 2:
        return set()
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry

    for i in range(n):
        _, vid_i, pkg_i = created[i]
        for j in range(i + 1, n):
            _, vid_j, pkg_j = created[j]
            if vid_i == vid_j or (bool(pkg_i) and bool(pkg_j) and pkg_i == pkg_j):
                union(i, j)
    comp: dict[int, list[str]] = defaultdict(list)
    for i in range(n):
        comp[find(i)].append(created[i][0])
    out: set[tuple[str, str]] = set()
    for members in comp.values():
        mlen = len(members)
        if mlen < 2:
            continue
        for i in range(mlen):
            for j in range(i + 1, mlen):
                a, b = members[i], members[j]
                out.add(_undirected_pair_key(a, b))
    return out


def _create_issue_relations_cve_or_pkg(
    api_key: str, pairs: set[tuple[str, str]],
) -> None:
    """``pairs`` = unique (min,max) id tuples; one ``issueRelationCreate`` per edge."""
    if not pairs:
        return
    n_ok, n_err = 0, 0
    for a, b in sorted(pairs):
        err = _link_issue_related_best_effort(api_key, a, b)
        if err:
            n_err += 1
            print(
                f"WARNING: could not add related link {a} <-> {b}: {err}",
                file=sys.stderr,
            )
        else:
            n_ok += 1
    # ok counts try successes + benign duplicates; pairs may re-run on a second sync
    print(
        f"Issue relations (same-CVE or same-PkgName components): "
        f"{n_ok} pair operation(s) OK, {n_err} error(s) ({len(pairs)} unique pair(s))."
    )


def _comment_has_refs_anchor(body: str) -> bool:
    if REFS_HTML_MARKER in body:
        return True
    if LEGACY_REFS_MARKER in body or REFS_SECTION_HEADER in body:
        return True
    return any(h in body for h in LEGACY_REFS_HEADERS)


def _get_marker_comment_id(
    api_key: str, issue_id: str
) -> tuple[str | None, str | None]:
    q = """
query IssueComments($issueId: String!) {
  issue(id: $issueId) {
    id
    comments {
      nodes {
        id
        body
      }
    }
  }
}
"""
    data = _graphql(api_key, q, {"issueId": issue_id})
    issue = data.get("issue")
    if not issue:
        return None, None
    for node in (issue.get("comments") or {}).get("nodes") or []:
        body = node.get("body") or ""
        if _comment_has_refs_anchor(body):
            return str(node["id"]), body
    return None, None


def _create_comment(api_key: str, issue_id: str, body: str) -> None:
    m = """
mutation CreateComment($input: CommentCreateInput!) {
  commentCreate(input: $input) {
    success
  }
}
"""
    data = _graphql(
        api_key,
        m,
        {"input": {"issueId": issue_id, "body": body}},
    )
    if not (data.get("commentCreate") or {}).get("success"):
        raise RuntimeError(f"commentCreate failed: {data}")


def _update_comment(api_key: str, comment_id: str, body: str) -> None:
    m = """
mutation CommentUpdate($id: String!, $input: CommentUpdateInput!) {
  commentUpdate(id: $id, input: $input) {
    success
  }
}
"""
    data = _graphql(
        api_key,
        m,
        {"id": comment_id, "input": {"body": body}},
    )
    if not (data.get("commentUpdate") or {}).get("success"):
        raise RuntimeError(f"commentUpdate failed: {data}")


def _sync_refs_comment(
    api_key: str,
    issue_id: str,
    scan_ref: ScanRef,
    short_sha: str,
    run_url: str,
) -> None:
    comment_id, prev_body = _get_marker_comment_id(api_key, issue_id)
    new_body = _merge_refs_comment(prev_body, scan_ref, short_sha, run_url)
    if comment_id:
        _update_comment(api_key, comment_id, new_body)
    else:
        _create_comment(api_key, issue_id, new_body)


def _resolve_linear_team_id() -> str:
    return (
        os.environ.get("LINEAR_TEAM_ID", "").strip()
        or os.environ.get("TRIVY_LINEAR_TEAM_ID", "").strip()
    )


def _resolve_linear_label_ids() -> list[str] | None:
    raw = os.environ.get("LINEAR_LABEL_IDS", "").strip() or os.environ.get(
        "TRIVY_LINEAR_LABEL_IDS", ""
    ).strip()
    return [x.strip() for x in raw.split(",") if x.strip()] or None


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--scanner",
        default=os.environ.get("SCANNER", "trivy"),
        help="Scanner id: trivy | trivy_grype (mixed Trivy + Grype JSON, deduped by image+CVE). "
        "Default: trivy.",
    )
    p.add_argument(
        "report_paths",
        nargs="+",
        type=Path,
        help="Report file(s) produced by the scanner (e.g. Trivy JSON)",
    )
    args = p.parse_args()
    scanner = args.scanner.strip().lower()

    api_key = os.environ.get("LINEAR_SECURITY_SCAN_API_KEY", "").strip()
    if not api_key:
        print("ERROR: Set LINEAR_SECURITY_SCAN_API_KEY", file=sys.stderr)
        return 1

    team_id = _resolve_linear_team_id()
    if not team_id:
        print(
            "ERROR: Set LINEAR_TEAM_ID (or legacy TRIVY_LINEAR_TEAM_ID) to the Linear team UUID",
            file=sys.stderr,
        )
        return 1

    base_label_ids = _resolve_linear_label_ids() or []
    repo_label_map = _resolve_linear_repo_label_map()

    if scanner not in SCANNERS:
        print(
            f"ERROR: Unknown scanner {scanner!r}. Implemented: {sorted(SCANNERS)}",
            file=sys.stderr,
        )
        return 1

    kind = os.environ.get("SCAN_REF_KIND", "").strip().lower()
    name = os.environ.get("SCAN_REF_NAME", "").strip()
    if kind not in ("branch", "tag") or not name:
        print(
            "ERROR: Set SCAN_REF_KIND to branch|tag and SCAN_REF_NAME "
            "(normalized ref from workflow)",
            file=sys.stderr,
        )
        return 1
    scan_ref = ScanRef(kind=kind, name=name)

    initial_state_id = _resolve_issue_create_state_id(api_key, team_id)

    commit_sha = os.environ.get("GITHUB_SHA", "unknown")
    short_sha = commit_sha[:7] if len(commit_sha) >= 7 else commit_sha
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_url = f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else ""

    groups = SCANNERS[scanner](list(args.report_paths))
    if not groups:
        print(f"No findings in reports for scanner {scanner!r}. Nothing to sync.")
        return 0

    created = 0
    updated = 0
    # (issue_id, vid, pkg_key) for each **created** issue this run — used for clique relations at end.
    created_in_run: list[tuple[str, str, str]] = []

    for group_key, occ in sorted(groups.items(), key=lambda x: x[0]):
        artifact_ref, _, _, first = occ[0]
        if "\x1f" in group_key:
            vid, repo_scope = group_key.split("\x1f", 1)
        else:
            vid = group_key
            repo_scope = _repo_scope_ticket_label(artifact_ref)
        linear_title = _linear_issue_title(vid, first, repo_scope, scanner=scanner)
        description_heading = _advisory_title_for_description(
            scanner, first, fallback=linear_title
        )
        description = _build_description(
            scanner,
            vid,
            occ,
            run_url,
            scan_ref,
            commit_sha,
            description_heading,
            repo_scope,
        )

        linear_priority: int | None = None
        linear_due_date: str | None = None
        if scanner in ("trivy", "trivy_grype"):
            worst = _worst_trivy_severity(occ)
            linear_priority = _linear_priority_for_scan_severity(worst)
            linear_due_date = _linear_due_date_for_scan_severity(worst)

        repo_lids = _repo_label_ids_for_occurrences(repo_label_map, occ)
        create_labels = _dedupe_preserve_order([*base_label_ids, *repo_lids])
        create_labels_arg: list[str] | None = (
            create_labels if create_labels else None
        )

        existing = _find_issue_by_title(api_key, team_id, linear_title)
        if existing:
            issue_id = existing
            _sync_refs_comment(api_key, issue_id, scan_ref, short_sha, run_url)
            if repo_lids:
                current = _issue_graphql_label_ids(api_key, issue_id)
                merged = _dedupe_preserve_order([*current, *repo_lids])
                if set(merged) != set(current):
                    _issue_update_label_ids(api_key, issue_id, merged)
            updated += 1
            print(f"Updated refs comment: {linear_title} ({issue_id})")
        else:
            issue_id = _create_issue(
                api_key,
                team_id,
                linear_title,
                description,
                create_labels_arg,
                linear_priority,
                initial_state_id,
                linear_due_date,
            )
            _sync_refs_comment(api_key, issue_id, scan_ref, short_sha, run_url)
            created += 1
            print(f"Created issue: {linear_title} ({issue_id})")
            pkg_key = (
                _trivy_pkg_name_for_title(first).strip()
                if scanner in ("trivy", "trivy_grype")
                else ""
            )
            created_in_run.append((issue_id, vid, pkg_key))

    if created_in_run:
        _create_issue_relations_cve_or_pkg(
            api_key, _issue_pairs_cve_or_pkg(created_in_run)
        )

    print(f"Done. Created {created}, updated refs on {updated} existing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
