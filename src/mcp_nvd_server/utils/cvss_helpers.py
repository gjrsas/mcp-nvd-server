from __future__ import annotations

from typing import Any

from mcp_nvd_server.models.cvss import (
    CVSSInterpretation,
    CVSSMetricValue,
    CVSSScore,
    NormalizedCVE,
    ParsedCVSSVector,
)


# ----------------------------
# Metric dictionaries
# ----------------------------

CVSS_V3_V31_LABELS: dict[str, dict[str, str]] = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"N": "None", "L": "Low", "H": "High"},
    "I": {"N": "None", "L": "Low", "H": "High"},
    "A": {"N": "None", "L": "Low", "H": "High"},
}

# Parser subset for v4.0. This covers common base metrics plus a few
# frequently encountered additional metrics. Unknown codes are preserved, not discarded.
CVSS_V4_LABELS: dict[str, dict[str, str]] = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "AT": {"N": "None", "P": "Present"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "P": "Passive", "A": "Active"},
    "VC": {"N": "None", "L": "Low", "H": "High"},
    "VI": {"N": "None", "L": "Low", "H": "High"},
    "VA": {"N": "None", "L": "Low", "H": "High"},
    "SC": {"N": "None", "L": "Low", "H": "High"},
    "SI": {"N": "None", "L": "Low", "H": "High"},
    "SA": {"N": "None", "L": "Low", "H": "High"},
    # A few common supplemental / environmental / threat codes :
    "E": {"X": "Not Defined", "A": "Attacked", "P": "POC", "U": "Unreported"},
}

CVSS_V2_LABELS: dict[str, dict[str, str]] = {
    "AV": {"L": "Local", "A": "Adjacent Network", "N": "Network"},
    "AC": {"H": "High", "M": "Medium", "L": "Low"},
    "Au": {"M": "Multiple", "S": "Single", "N": "None"},
    "C": {"N": "None", "P": "Partial", "C": "Complete"},
    "I": {"N": "None", "P": "Partial", "C": "Complete"},
    "A": {"N": "None", "P": "Partial", "C": "Complete"},
}


def _dedupe(seq: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _coerce_source(source: str | None, source_label: str | None = None) -> str:
    s = (source or source_label or "").strip().lower()
    if "nist" in s or "nvd" in s:
        return "nvd"
    if "cna" in s:
        return "cna"
    if s:
        return "other"
    return "unknown"


# ----------------------------
# 1) parse_cvss_vector()
# ----------------------------

def parse_cvss_vector(vector: str | None) -> ParsedCVSSVector | None:
    """
    Parse CVSS v2.0, v3.0, v3.1, or v4.0 vectors into labeled metric dictionaries.

    Notes:
    - This is a parser/labeler, not a score calculator.
    - Unknown metrics are preserved in unknown_metrics.
    """
    if not vector:
        return None

    raw = vector.strip()
    errors: list[str] = []

    if raw.startswith("CVSS:4.0/"):
        version = "4.0"
        parts = raw.split("/")[1:]  # skips CVSS:4.0
        labels_map = CVSS_V4_LABELS
    elif raw.startswith("CVSS:3.1/"):
        version = "3.1"
        parts = raw.split("/")[1:]
        labels_map = CVSS_V3_V31_LABELS
    elif raw.startswith("CVSS:3.0/"):
        version = "3.0"
        parts = raw.split("/")[1:]
        labels_map = CVSS_V3_V31_LABELS
    else:
        # Treat as v2.0-style vector if it lacks the CVSS prefix.
        version = "2.0"
        parts = raw.split("/")
        labels_map = CVSS_V2_LABELS

    metrics: dict[str, CVSSMetricValue] = {}
    unknown_metrics: dict[str, str] = {}

    for part in parts:
        if ":" not in part:
            errors.append(f"Malformed metric segment: {part}")
            continue

        code, value = part.split(":", 1)
        code = code.strip()
        value = value.strip()

        if not code or not value:
            errors.append(f"Malformed metric segment: {part}")
            continue

        if code in labels_map:
            label = labels_map[code].get(value)
            if label is None:
                unknown_metrics[code] = value
                errors.append(f"Unknown value '{value}' for metric '{code}'")
            else:
                metrics[code] = CVSSMetricValue(code=value, label=label)
        else:
            unknown_metrics[code] = value

    return ParsedCVSSVector(
        raw_vector=raw,
        version=version,
        metrics=metrics,
        unknown_metrics=unknown_metrics,
        valid=len(errors) == 0,
        errors=errors,
    )


# ----------------------------
# Helpers to extract NVD metric blocks
# ----------------------------

def _make_score(
    version: str,
    metric_entry: dict[str, Any],
    source: str = "unknown",
    source_label: str | None = None,
) -> CVSSScore:
    cvss_data = metric_entry.get("cvssData", {}) if isinstance(metric_entry, dict) else {}
    vector = cvss_data.get("vectorString")
    parsed = parse_cvss_vector(vector)

    return CVSSScore(
        version=version,
        source=_coerce_source(source, source_label),
        source_label=source_label,
        base_score=cvss_data.get("baseScore"),
        base_severity=metric_entry.get("baseSeverity") or cvss_data.get("baseSeverity"),
        vector=vector,
        exploitability_score=metric_entry.get("exploitabilityScore"),
        impact_score=metric_entry.get("impactScore"),
        parsed_vector=parsed,
    )


def extract_all_cvss_scores(cve: dict[str, Any]) -> list[CVSSScore]:
    """
    Pull all discoverable CVSS metric blocks out of an NVD CVE object.

    Handles common NVD keys:
    - cvssMetricV40
    - cvssMetricV31
    - cvssMetricV30
    - cvssMetricV2

    Each list may contain NVD and/or CNA-provided values.
    """
    metrics = cve.get("metrics", {}) or {}
    scores: list[CVSSScore] = []

    mapping = [
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]

    for key, version in mapping:
        for entry in metrics.get(key, []) or []:
            source = entry.get("type") or entry.get("source") or "unknown"
            source_label = entry.get("source")
            scores.append(_make_score(version, entry, source=source, source_label=source_label))

    return scores


# ----------------------------
# 2) extract_preferred_cvss()
# ----------------------------

def extract_preferred_cvss(cve: dict[str, Any]) -> CVSSScore | None:
    """
    Choose a preferred CVSS score with stable precedence:

    1. NVD v4.0
    2. NVD v3.1
    3. NVD v3.0
    4. NVD v2.0
    5. CNA/other v4.0
    6. CNA/other v3.1
    7. CNA/other v3.0
    8. CNA/other v2.0

    This keeps NVD as primary when available, while still surfacing CNA values
    if NVD has not yet provided its own assessment.
    """
    scores = extract_all_cvss_scores(cve)
    if not scores:
        return None

    version_rank = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}
    source_rank = {"nvd": 2, "cna": 1, "other": 0, "unknown": 0}

    def sort_key(score: CVSSScore) -> tuple[int, int]:
        return (
            source_rank.get(score.source, 0),
            version_rank.get(str(score.version), 0),
        )

    # Prefer source first, then version, per the policy above.
    return sorted(scores, key=sort_key, reverse=True)[0]


# ----------------------------
# 3) build_cvss_interpretation()
# ----------------------------

def build_cvss_interpretation(score: CVSSScore | None) -> CVSSInterpretation | None:
    """
    Produce a plain-English interpretation from the preferred CVSS score/vector.

    This is intentionally explanatory rather than mathematically complete.
    """
    if score is None:
        return None

    notes = ["CVSS reflects severity, not overall organizational risk."]
    parsed = score.parsed_vector

    severity_note = None
    if score.base_score is not None or score.base_severity:
        if score.base_score is not None and score.base_severity:
            severity_note = f"Base severity is {score.base_severity} ({score.base_score})."
        elif score.base_severity:
            severity_note = f"Base severity is {score.base_severity}."
        else:
            severity_note = f"Base score is {score.base_score}."

    if parsed is None:
        return CVSSInterpretation(
            severity_note=severity_note,
            analyst_summary="CVSS data is present but no vector string was available to interpret.",
            notes=notes,
        )

    m = parsed.metrics

    exploitability_bits: list[str] = []
    impact_bits: list[str] = []
    requirement_bits: list[str] = []

    # Version-specific interpretation
    if parsed.version in {"3.0", "3.1"}:
        av = m.get("AV")
        pr = m.get("PR")
        ui = m.get("UI")
        ac = m.get("AC")
        s = m.get("S")
        c = m.get("C")
        i = m.get("I")
        a = m.get("A")

        if av:
            exploitability_bits.append(f"attack vector is {av.label.lower()}")
        if pr:
            requirement_bits.append(f"privileges required: {pr.label.lower()}")
        if ui:
            requirement_bits.append(f"user interaction: {ui.label.lower()}")
        if ac:
            requirement_bits.append(f"attack complexity: {ac.label.lower()}")

        cia = []
        if c:
            cia.append(f"confidentiality {c.label.lower()}")
        if i:
            cia.append(f"integrity {i.label.lower()}")
        if a:
            cia.append(f"availability {a.label.lower()}")

        if cia:
            impact_bits.append("impact to " + ", ".join(cia))

        if s:
            impact_bits.append(f"scope is {s.label.lower()}")

    elif parsed.version == "4.0":
        av = m.get("AV")
        pr = m.get("PR")
        ui = m.get("UI")
        ac = m.get("AC")
        at = m.get("AT")
        vc = m.get("VC")
        vi = m.get("VI")
        va = m.get("VA")
        sc = m.get("SC")
        si = m.get("SI")
        sa = m.get("SA")

        if av:
            exploitability_bits.append(f"attack vector is {av.label.lower()}")
        if pr:
            requirement_bits.append(f"privileges required: {pr.label.lower()}")
        if ui:
            requirement_bits.append(f"user interaction: {ui.label.lower()}")
        if ac:
            requirement_bits.append(f"attack complexity: {ac.label.lower()}")
        if at:
            requirement_bits.append(f"attack requirements: {at.label.lower()}")

        vuln_sys = []
        sub_sys = []
        if vc:
            vuln_sys.append(f"confidentiality {vc.label.lower()}")
        if vi:
            vuln_sys.append(f"integrity {vi.label.lower()}")
        if va:
            vuln_sys.append(f"availability {va.label.lower()}")
        if sc:
            sub_sys.append(f"subsequent system confidentiality {sc.label.lower()}")
        if si:
            sub_sys.append(f"subsequent system integrity {si.label.lower()}")
        if sa:
            sub_sys.append(f"subsequent system availability {sa.label.lower()}")

        if vuln_sys:
            impact_bits.append("impact to vulnerable system: " + ", ".join(vuln_sys))
        if sub_sys:
            impact_bits.append("impact to subsequent systems: " + ", ".join(sub_sys))

    elif parsed.version == "2.0":
        av = m.get("AV")
        au = m.get("Au")
        ac = m.get("AC")
        c = m.get("C")
        i = m.get("I")
        a = m.get("A")

        if av:
            exploitability_bits.append(f"attack vector is {av.label.lower()}")
        if au:
            requirement_bits.append(f"authentication: {au.label.lower()}")
        if ac:
            requirement_bits.append(f"attack complexity: {ac.label.lower()}")

        cia = []
        if c:
            cia.append(f"confidentiality {c.label.lower()}")
        if i:
            cia.append(f"integrity {i.label.lower()}")
        if a:
            cia.append(f"availability {a.label.lower()}")

        if cia:
            impact_bits.append("impact to " + ", ".join(cia))

    exploitability_summary = None
    if exploitability_bits:
        exploitability_summary = ", ".join(exploitability_bits).capitalize() + "."

    attack_requirements_summary = None
    if requirement_bits:
        attack_requirements_summary = ", ".join(requirement_bits).capitalize() + "."

    impact_summary = None
    if impact_bits:
        impact_summary = "; ".join(impact_bits).capitalize() + "."

    analyst_parts = []
    if severity_note:
        analyst_parts.append(severity_note)
    if exploitability_summary:
        analyst_parts.append(exploitability_summary)
    if attack_requirements_summary:
        analyst_parts.append(attack_requirements_summary)
    if impact_summary:
        analyst_parts.append(impact_summary)

    defender_summary = None
    if parsed.version in {"3.0", "3.1", "4.0"}:
        av = m.get("AV")
        pr = m.get("PR")
        ui = m.get("UI")
        if av and av.label == "Network" and pr and pr.label == "None" and ui and ui.label in {"None", "Passive"}:
            defender_summary = (
                "This appears remotely reachable without authentication and with little or no user mediation."
            )
    if defender_summary is None and score.base_severity in {"CRITICAL", "HIGH"}:
        defender_summary = "This should be reviewed promptly, especially for exposed or internet-facing assets."

    return CVSSInterpretation(
        severity_note=severity_note,
        exploitability_summary=exploitability_summary,
        impact_summary=impact_summary,
        attack_requirements_summary=attack_requirements_summary,
        analyst_summary=" ".join(analyst_parts) if analyst_parts else None,
        defender_summary=defender_summary,
        notes=notes,
    )


# ----------------------------
# Convenience builder for service layer
# ----------------------------

def build_normalized_cve(
    *,
    cve_id: str,
    published: str | None,
    last_modified: str | None,
    description: str | None,
    cwe: list[str] | None = None,
    cpes: list[str] | None = None,
    references: list[dict[str, Any]] | None = None,
    raw_cve: dict[str, Any],
    kev: dict[str, Any] | None = None,
) -> NormalizedCVE:
    scores = extract_all_cvss_scores(raw_cve)
    preferred = extract_preferred_cvss(raw_cve)
    interpretation = build_cvss_interpretation(preferred)

    return NormalizedCVE(
        cve_id=cve_id,
        published=published,
        last_modified=last_modified,
        description=description,
        severity=preferred.base_severity if preferred else None,
        base_score=preferred.base_score if preferred else None,
        cwe=cwe or [],
        cpes=cpes or [],
        references=references or [],
        preferred_cvss=preferred,
        cvss_scores=scores,
        cvss_versions_available=_dedupe([str(s.version) for s in scores]),
        cvss_interpretation=interpretation,
        kev=kev or {},
    )
