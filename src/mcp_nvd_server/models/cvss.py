"""CVSS-related models live here.

This module is intentionally minimal for now because the service currently
normalizes only the two CVSS fields it exposes in ``CVESummary``:

- ``severity`` for the qualitative rating such as ``HIGH`` or ``CRITICAL``
- ``base_score`` for the numeric score from 0.0 to 10.0

When the project grows to support richer CVSS output, this is the place
to add typed models for:

- version-specific metric payloads such as CVSS v3.1 and v2
- vector strings and exploitability/impact subscores
- normalization helpers shared by CVE and search responses


Keeping this file separate from ``cve.py`` leaves room for CVSS-specific
 models without making the main CVE response models harder to scan.

No concrete models are defined yet because the current API surface only needs
normalized summary fields, and those already live in ``CVESummary``.
"""


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from mcp_nvd_server.models.kev import CisaKevMetadata


CVSSVersion = Literal["2.0", "3.0", "3.1", "4.0"]
CVSSSource = Literal["nvd", "cna", "other", "unknown"]


class CVSSMetricValue(BaseModel):
    code: str
    label: str


class ParsedCVSSVector(BaseModel):
    raw_vector: str
    version: CVSSVersion | str
    metrics: dict[str, CVSSMetricValue] = Field(default_factory=dict)
    unknown_metrics: dict[str, str] = Field(default_factory=dict)
    valid: bool = True
    errors: list[str] = Field(default_factory=list)


class CVSSScore(BaseModel):
    version: CVSSVersion | str
    source: CVSSSource = "unknown"
    source_label: str | None = None

    base_score: float | None = None
    base_severity: str | None = None
    vector: str | None = None

    exploitability_score: float | None = None
    impact_score: float | None = None

    parsed_vector: ParsedCVSSVector | None = None


class CVSSInterpretation(BaseModel):
    severity_note: str | None = None
    exploitability_summary: str | None = None
    impact_summary: str | None = None
    attack_requirements_summary: str | None = None
    analyst_summary: str | None = None
    defender_summary: str | None = None
    notes: list[str] = Field(default_factory=list)


class NormalizedCVE(BaseModel):
    cve_id: str
    published: str | None = None
    last_modified: str | None = None
    description: str | None = None
    severity: str | None = None
    base_score: float | None = None

    cwe: list[str] = Field(default_factory=list)
    cpes: list[str] = Field(default_factory=list)
    references: list[dict] = Field(default_factory=list)

    preferred_cvss: CVSSScore | None = None
    cvss_scores: list[CVSSScore] = Field(default_factory=list)
    cvss_versions_available: list[str] = Field(default_factory=list)
    cvss_interpretation: CVSSInterpretation | None = None

    cisa_kev_metadata: CisaKevMetadata | None = None
