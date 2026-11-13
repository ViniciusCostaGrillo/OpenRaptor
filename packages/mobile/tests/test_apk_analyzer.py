"""Tests for Android APK analyzer and Ghidra native lib handoff."""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

import pytest

from packages.mobile.apk_analyzer import analyze_apk, parse_android_manifest


def _build_synthetic_apk(apk_path: Path, *, include_zip_slip: bool = False) -> None:
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.acme.wallet">
  <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true" />
    <service android:name=".SyncService" android:exported="true" android:permission="com.acme.PERM" />
    <receiver android:name=".BootReceiver" android:exported="true" />
  </application>
</manifest>"""
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("assets/config.json", '{"api":"https://api.acme.internal/v2","token":"AIzaSyDummyFirebaseKey1234567890"}')
        zf.writestr("lib/arm64-v8a/libcrypto_native.so", b"\x7fELF\x02\x01\x01\x00dummy")
        if include_zip_slip:
            zf.writestr("../../evil.txt", b"pwned")


class TestApkAnalyzer:
    def test_parse_android_manifest_detects_flags_and_exported_components(self) -> None:
        manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.acme.wallet">
  <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true" />
    <service android:name=".SyncService" android:exported="true" android:permission="com.acme.PERM" />
  </application>
</manifest>"""
        parsed = parse_android_manifest(manifest)
        assert parsed["package_name"] == "com.acme.wallet"
        assert parsed["flags"]["debuggable"] is True
        assert parsed["flags"]["allowBackup"] is True
        assert parsed["flags"]["usesCleartextTraffic"] is True
        assert ".MainActivity" in parsed["unprotected_exported"]
        assert ".SyncService" not in parsed["unprotected_exported"]

    def test_analyze_apk_extracts_so_secrets_endpoints_and_blocks_zip_slip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        apk = tmp_path / "app.apk"
        _build_synthetic_apk(apk, include_zip_slip=True)
        out_dir = tmp_path / "out"

        result = analyze_apk(apk, out_dir, run_jadx=False, run_apktool=False)
        assert result.package_name == "com.acme.wallet"
        assert any("https://api.acme.internal/v2" in ep for ep in result.endpoints)
        assert any("AIzaSyDummyFirebaseKey1234567890" in sec["match"] for sec in result.secrets)
        assert len(result.native_libs) == 1
        assert result.native_libs[0].name == "libcrypto_native.so"
        assert not (tmp_path / "evil.txt").exists()
