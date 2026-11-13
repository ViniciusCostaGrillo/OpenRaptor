"""Android APK analyzer with safe extraction, manifest audit, secret/endpoint scan, and .so Ghidra handoff."""

from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import defusedxml.ElementTree as DET

from packages.hunt.evidence_store import EvidenceStore

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("bearer_jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
)


@dataclass
class ApkAnalysisResult:
    """Structured result of analyzing an Android APK."""

    apk_path: Path
    package_name: str = ""
    manifest_flags: dict[str, bool] = field(default_factory=dict)
    unprotected_exported: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    secrets: list[dict[str, str]] = field(default_factory=list)
    native_libs: list[Path] = field(default_factory=list)
    ghidra_targets: list[str] = field(default_factory=list)


def parse_android_manifest(manifest_xml: str) -> dict[str, Any]:
    """Parse decoded AndroidManifest.xml for insecure flags and exported components."""
    result: dict[str, Any] = {
        "package_name": "",
        "flags": {"debuggable": False, "allowBackup": False, "usesCleartextTraffic": False},
        "unprotected_exported": [],
    }
    if not manifest_xml.strip():
        return result
    try:
        root = DET.fromstring(manifest_xml)
    except Exception:
        return result

    result["package_name"] = root.attrib.get("package", "")
    app = root.find("application")
    if app is None:
        return result

    for flag in ("debuggable", "allowBackup", "usesCleartextTraffic"):
        val = app.attrib.get(f"{_ANDROID_NS}{flag}", "").lower()
        result["flags"][flag] = val == "true"

    for tag in ("activity", "service", "receiver", "provider"):
        for comp in app.findall(tag):
            exported = comp.attrib.get(f"{_ANDROID_NS}exported", "").lower()
            perm = comp.attrib.get(f"{_ANDROID_NS}permission", "")
            name = comp.attrib.get(f"{_ANDROID_NS}name", "")
            if exported == "true" and not perm and name:
                result["unprotected_exported"].append(name)

    return result


def _safe_extract_zip(apk_path: Path, dest_dir: Path) -> list[Path]:
    extracted: list[Path] = []
    dest_resolved = dest_dir.resolve()
    dest_resolved.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(apk_path, "r") as zf:
        for member in zf.infolist():
            if member.is_dir():
                continue
            target = (dest_resolved / member.filename).resolve()
            if not target.is_relative_to(dest_resolved):
                continue  # Block Zip Slip
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member, "r") as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted.append(target)
    return extracted


def _scan_text_tree(root_dir: Path) -> tuple[list[str], list[dict[str, str]]]:
    endpoints: set[str] = set()
    secrets: list[dict[str, str]] = []
    text_exts = {".json", ".xml", ".txt", ".properties", ".js", ".java", ".kt", ".smali", ".yml", ".yaml"}
    for path in root_dir.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in text_exts:
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for url in _URL_RE.findall(content):
            if not url.startswith("http://schemas.android.com"):
                endpoints.add(url)
        for kind, pattern in _SECRET_PATTERNS:
            for match in pattern.findall(content):
                secrets.append({"kind": kind, "match": match, "file": str(path.relative_to(root_dir))})
    return sorted(endpoints), secrets


def analyze_apk(
    apk_path: Path,
    out_dir: Path,
    *,
    run_jadx: bool = True,
    run_apktool: bool = True,
) -> ApkAnalysisResult:
    """Analyze an Android APK, extract native .so libraries, and record findings."""
    apk = Path(apk_path)
    out = Path(out_dir)
    work_dir = out / "mobile"
    unzip_dir = work_dir / "unzipped"
    extracted = _safe_extract_zip(apk, unzip_dir)

    if run_apktool and shutil.which("apktool"):
        subprocess.run(
            ["apktool", "d", "-f", "-o", str(work_dir / "apktool"), str(apk)],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    if run_jadx and shutil.which("jadx"):
        subprocess.run(
            ["jadx", "-d", str(work_dir / "jadx"), str(apk)],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )

    manifest_candidates = [
        work_dir / "apktool" / "AndroidManifest.xml",
        unzip_dir / "AndroidManifest.xml",
    ]
    manifest_info: dict[str, Any] = {
        "package_name": "",
        "flags": {"debuggable": False, "allowBackup": False, "usesCleartextTraffic": False},
        "unprotected_exported": [],
    }
    for mpath in manifest_candidates:
        if mpath.is_file():
            raw_xml = mpath.read_text(encoding="utf-8", errors="ignore")
            if "<manifest" in raw_xml:
                manifest_info = parse_android_manifest(raw_xml)
                break

    endpoints, secrets = _scan_text_tree(work_dir)
    native_libs = [p for p in extracted if p.suffix.lower() == ".so"]
    ghidra_targets = [str(p) for p in native_libs]

    store = EvidenceStore(out)
    flags = manifest_info["flags"]
    if flags.get("debuggable"):
        store.record_finding(
            title="Android application is debuggable (android:debuggable=true)",
            vuln_type="mobile_misconfig",
            target=str(apk),
            severity="high",
            tool="apk_analyzer",
            cwe_id="CWE-489",
            remediation="Set android:debuggable='false' in release builds.",
        )
    if flags.get("usesCleartextTraffic"):
        store.record_finding(
            title="Android application allows cleartext HTTP traffic",
            vuln_type="cleartext_traffic",
            target=str(apk),
            severity="medium",
            tool="apk_analyzer",
            cwe_id="CWE-319",
            remediation="Disable usesCleartextTraffic and enforce HTTPS with Network Security Config.",
        )
    for comp in manifest_info["unprotected_exported"]:
        store.record_finding(
            title=f"Unprotected exported Android component: {comp}",
            vuln_type="exported_component",
            target=str(apk),
            severity="medium",
            tool="apk_analyzer",
            cwe_id="CWE-926",
            remediation="Set android:exported='false' or require a signature-level permission.",
        )
    for sec in secrets:
        store.record_finding(
            title=f"Hardcoded secret ({sec['kind']}) in APK",
            vuln_type="hardcoded_secret",
            target=f"{apk}:{sec['file']}",
            severity="high",
            tool="apk_analyzer",
            cwe_id="CWE-798",
            evidence=sec["match"],
            remediation="Remove hardcoded secrets from the client APK and fetch short-lived tokens server-side.",
        )

    return ApkAnalysisResult(
        apk_path=apk,
        package_name=manifest_info["package_name"],
        manifest_flags=flags,
        unprotected_exported=manifest_info["unprotected_exported"],
        endpoints=endpoints,
        secrets=secrets,
        native_libs=native_libs,
        ghidra_targets=ghidra_targets,
    )
