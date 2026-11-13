"""Target classifier for routing /hunt workflows."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlparse


class TargetKind(StrEnum):
    """Supported OpenRaptor /hunt target classifications."""

    URL = "url"
    EXTERNAL_DOMAIN = "external_domain"
    IP_CIDR = "ip_cidr"
    APK = "apk"
    IPA = "ipa"
    BINARY = "binary"
    REPO = "repo"


@dataclass(frozen=True)
class TargetClassification:
    """Result of classifying an operator-supplied target."""

    target: str
    kind: TargetKind
    recommended_pipeline: str


def classify_target(target: str) -> TargetClassification:
    """Classify a target string into a network, mobile, binary, or repo workflow."""
    raw = target.strip()
    parsed = urlparse(raw)

    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return TargetClassification(
            target=raw,
            kind=TargetKind.URL,
            recommended_pipeline="web_recon_and_active",
        )

    try:
        ipaddress.ip_network(raw, strict=False)
        return TargetClassification(
            target=raw,
            kind=TargetKind.IP_CIDR,
            recommended_pipeline="infra_nmap_and_web",
        )
    except ValueError:
        pass

    candidate = Path(raw)
    if candidate.exists():
        if candidate.is_dir():
            return TargetClassification(
                target=str(candidate),
                kind=TargetKind.REPO,
                recommended_pipeline="sast_agentic",
            )
        suffix = candidate.suffix.lower()
        if suffix == ".apk":
            return TargetClassification(
                target=str(candidate),
                kind=TargetKind.APK,
                recommended_pipeline="mobile_apk_and_ghidra",
            )
        if suffix == ".ipa":
            return TargetClassification(
                target=str(candidate),
                kind=TargetKind.IPA,
                recommended_pipeline="mobile_ipa_future",
            )
        return TargetClassification(
            target=str(candidate),
            kind=TargetKind.BINARY,
            recommended_pipeline="binary_ghidra_and_fuzz",
        )

    lower = raw.lower()
    if lower.endswith(".apk"):
        return TargetClassification(
            target=raw,
            kind=TargetKind.APK,
            recommended_pipeline="mobile_apk_and_ghidra",
        )
    if lower.endswith(".ipa"):
        return TargetClassification(
            target=raw,
            kind=TargetKind.IPA,
            recommended_pipeline="mobile_ipa_future",
        )

    return TargetClassification(
        target=raw,
        kind=TargetKind.EXTERNAL_DOMAIN,
        recommended_pipeline="external_recon_and_web",
    )
