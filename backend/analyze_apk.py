#!/usr/bin/env python3
"""Local-first Android APK static triage for AppPath.

This performs static inspection only. It never installs or executes the APK.
Findings are indicators for human review, not proof of exploitability.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
import warnings
import zipfile
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
MASVS_GROUPS = (
    "MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-AUTH", "MASVS-NETWORK",
    "MASVS-PLATFORM", "MASVS-CODE", "MASVS-RESILIENCE", "MASVS-PRIVACY",
)


def map_masvs_groups(category: str, title: str) -> list[str]:
    """Broad OWASP MASVS group mapping; deliberately not a control-level claim."""
    text = f"{category} {title}".lower()
    groups: list[str] = []
    if any(word in text for word in ("secret", "credential", "password", "token", "private key")):
        groups.extend(("MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-CODE"))
    if any(word in text for word in ("crypto", "cipher", "digest", "random", "md5", "sha-1", "ecb", "des")):
        groups.append("MASVS-CRYPTO")
    if any(word in text for word in ("http", "cleartext", "network", "endpoint", "traffic")):
        groups.append("MASVS-NETWORK")
    if any(word in text for word in ("component", "exported", "manifest", "debuggable")):
        groups.extend(("MASVS-PLATFORM", "MASVS-CODE"))
    if any(word in text for word in ("permission", "privacy", "location", "contacts", "sms", "camera", "audio")):
        groups.extend(("MASVS-PRIVACY", "MASVS-PLATFORM"))
    if not groups:
        groups.append("MASVS-CODE")
    return list(dict.fromkeys(groups))

SENSITIVE_PERMISSIONS = {
    "android.permission.SEND_SMS": ("high", "Can send SMS messages; confirm this is essential for the app."),
    "android.permission.READ_SMS": ("high", "Can access SMS messages; review whether the app genuinely needs this."),
    "android.permission.RECEIVE_SMS": ("high", "Can receive SMS broadcasts; review whether the app genuinely needs this."),
    "android.permission.READ_CALL_LOG": ("high", "Can access call history; confirm necessity and user consent."),
    "android.permission.WRITE_CALL_LOG": ("high", "Can modify call history; confirm necessity and user consent."),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("high", "Requests broad file access; prefer narrower scoped storage where possible."),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("high", "Can request installation of other packages; verify the feature and safeguards."),
    "android.permission.READ_CONTACTS": ("medium", "Can access contacts; verify purpose, consent, and data minimization."),
    "android.permission.WRITE_CONTACTS": ("medium", "Can modify contacts; verify purpose and consent."),
    "android.permission.ACCESS_FINE_LOCATION": ("medium", "Can access precise location; verify purpose and permission timing."),
    "android.permission.ACCESS_COARSE_LOCATION": ("low", "Can access approximate location; verify necessity and consent."),
    "android.permission.RECORD_AUDIO": ("medium", "Can record audio; verify when and why recording occurs."),
    "android.permission.CAMERA": ("low", "Can use the camera; confirm the app requests access only when needed."),
    "android.permission.READ_PHONE_STATE": ("medium", "Can access phone-state information; verify necessity."),
    "android.permission.READ_PHONE_NUMBERS": ("medium", "Can access phone numbers; verify necessity and consent."),
    "android.permission.SYSTEM_ALERT_WINDOW": ("medium", "Can draw overlays above other apps; review misuse and user-consent risks."),
    "android.permission.QUERY_ALL_PACKAGES": ("medium", "Can query many installed apps; review whether a narrower package visibility declaration works."),
    "android.permission.BLUETOOTH_SCAN": ("low", "Can scan nearby Bluetooth devices; verify the app's stated purpose."),
}

URL_RE = re.compile(rb"https?://[^\s\"'<>\\]{4,}", re.IGNORECASE)
CRYPTO_PATTERNS = (
    (re.compile(r"(?i)\bAES/ECB(?:/[A-Z0-9_-]+)?\b"), "ECB cipher mode indicator", "medium", "ECB mode is generally not appropriate for encrypting structured application data because it reveals repeated plaintext blocks."),
    (re.compile(r"(?i)(?:^|[^A-Z0-9])(?:DES|DESede|3DES|RC2)(?:/|$|[^A-Z0-9])"), "Legacy cipher identifier", "medium", "The DEX contains a legacy cipher identifier. Confirm whether the algorithm is actually used for security-sensitive data."),
    (re.compile(r"(?i)\bMD5\b"), "MD5 digest identifier", "low", "MD5 is unsuitable where collision resistance is required. Confirm its use and replace security-sensitive digesting with a suitable modern construction."),
    (re.compile(r"(?i)\bSHA-?1\b"), "SHA-1 digest identifier", "low", "SHA-1 is deprecated for collision-resistant security use. Confirm the context and use a modern algorithm where appropriate."),
    (re.compile(r"(?i)(?:java[./]util[./]Random|Ljava/util/Random;)"), "General-purpose Random class indicator", "low", "java.util.Random is not a cryptographically secure random generator. Confirm whether it is used for tokens, keys, or other security-sensitive values."),
)
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{5,}")
SECRET_RE = re.compile(
    r"\b(api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|private[_-]?key)\b\s*[:=]\s*[\"']?([A-Za-z0-9_./+=\-]{8,})",
    re.IGNORECASE,
)
AWS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")


def attr(element, name: str, default: str = "") -> str:
    if element is None:
        return default
    return str(element.get(ANDROID_NS + name, default) or default)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_endpoint(raw: str) -> str | None:
    raw = raw.rstrip(".,;:)]}")
    try:
        parts = urlsplit(raw)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        hostname = parts.hostname
        if parts.port:
            hostname += f":{parts.port}"
        path = re.sub(r"(?i)/(token|secret|password|api[_-]?key)/[^/]+", r"/\1/[REDACTED]", parts.path)
        # Query strings and fragments may contain credentials, so omit them.
        return urlunsplit((parts.scheme.lower(), hostname, path[:160], "", ""))
    except Exception:
        return None


def masked(value: str) -> str:
    value = re.sub(r"\s+", " ", value)
    if len(value) <= 8:
        return value[:2] + "…"
    return value[:4] + "…" + value[-3:]


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"ok": False, "error": "Usage: python analyze_apk.py <path-to-apk>"}))
        return 0

    path = Path(sys.argv[1])
    try:
        if not path.is_file() or path.suffix.lower() != ".apk":
            raise ValueError("Please select a valid .apk file.")
        if path.stat().st_size > 100 * 1024 * 1024:
            raise ValueError("This prototype limits APK files to 100 MB to protect memory on this computer.")
        if not zipfile.is_zipfile(path):
            raise ValueError("The selected file is not a valid ZIP-based APK archive.")
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > 20000:
                raise ValueError("The APK archive contains an unusually large number of entries; scanning was stopped for safety.")
            if sum(item.file_size for item in infos) > 600 * 1024 * 1024:
                raise ValueError("The uncompressed archive is too large for the current safe-analysis limit.")
            names = {item.filename for item in infos}
            if "AndroidManifest.xml" not in names:
                raise ValueError("AndroidManifest.xml was not found. This file may not be a valid Android APK.")
            dex_infos = sorted((item for item in infos if re.fullmatch(r"classes(?:\d+)?\.dex", item.filename)), key=lambda item: item.filename)
            # Bound aggregate DEX data to keep this prototype usable on 8 GB RAM PCs.
            dex_names = []
            dex_total = 0
            for item in dex_infos:
                if item.file_size > 50 * 1024 * 1024 or len(dex_names) >= 20:
                    continue
                if dex_total + item.file_size > 120 * 1024 * 1024:
                    break
                dex_names.append(item.filename)
                dex_total += item.file_size

        try:
            from androguard.core.apk import APK
        except ImportError as exc:
            raise RuntimeError("Androguard is not installed. In the AppPath folder run: python -m pip install -r requirements.txt") from exc

        apk = APK(str(path))
        if hasattr(apk, "is_valid_APK") and not apk.is_valid_APK():
            raise ValueError("Androguard could not validate this APK's Android structure.")

        manifest = apk.get_android_manifest_xml()
        root = manifest.getroot() if hasattr(manifest, "getroot") else manifest
        if root is None:
            raise ValueError("Unable to read the APK Android manifest.")
        app_node = root.find("application")
        package_name = apk.get_package() or "Unknown package"
        version_name = apk.get_androidversion_name() or "Unknown"
        version_code = apk.get_androidversion_code() or "Unknown"
        try:
            min_sdk = apk.get_min_sdk_version() or "Unknown"
        except Exception:
            min_sdk = "Unknown"
        try:
            target_sdk = apk.get_target_sdk_version() or "Unknown"
        except Exception:
            target_sdk = "Unknown"

        permissions = sorted(set(apk.get_permissions() or []))
        findings: list[dict] = []
        find_counter = 0

        def add_finding(severity: str, category: str, title: str, description: str, evidence: str, recommendation: str) -> None:
            nonlocal find_counter
            find_counter += 1
            slug = re.sub(r"[^A-Z0-9]+", "-", f"{category}-{title}".upper()).strip("-")[:80]
            groups = map_masvs_groups(category, title)
            findings.append({
                "id": f"AP-{find_counter:03d}",
                "rule_id": f"APPPATH-{slug}",
                "severity": severity,
                "category": category,
                "title": title,
                "description": description,
                "evidence": evidence,
                "recommendation": recommendation,
                "masvs_groups": groups,
                "confidence_label": "Static indicator — review required",
            })

        # Manifest configuration checks.
        if app_node is not None:
            if attr(app_node, "debuggable").lower() == "true":
                add_finding("high", "Manifest", "Debuggable application build", "The manifest explicitly enables debugging. Debuggable builds may expose diagnostic capabilities and should not normally be shipped to end users.", "android:debuggable=\"true\"", "Disable debugging in release builds and verify the final build variant.")
            if attr(app_node, "usesCleartextTraffic").lower() == "true":
                add_finding("medium", "Network", "Cleartext traffic is enabled", "The manifest explicitly permits cleartext HTTP traffic. Sensitive data sent over HTTP can be exposed on an untrusted network.", "android:usesCleartextTraffic=\"true\"", "Prefer HTTPS, disable cleartext traffic, and review any narrowly scoped network security configuration exceptions.")

        components: list[dict] = []
        component_tags = ("activity", "activity-alias", "service", "receiver", "provider")
        if app_node is not None:
            app_permission = attr(app_node, "permission")
            for node in list(app_node):
                tag = node.tag.rsplit("}", 1)[-1]
                if tag not in component_tags:
                    continue
                name = attr(node, "name") or "(unnamed component)"
                exported_raw = attr(node, "exported")
                explicitly_exported = exported_raw.lower() == "true"
                has_intent_filter = any(child.tag.rsplit("}", 1)[-1] == "intent-filter" for child in list(node))
                component_permission = attr(node, "permission") or app_permission
                component = {
                    "type": tag,
                    "name": name,
                    "exported": explicitly_exported if exported_raw else None,
                    "has_intent_filter": has_intent_filter,
                    "permission": component_permission or "None declared",
                }
                components.append(component)
                if explicitly_exported and not component_permission:
                    add_finding(
                        "medium", "Components", "Exported component has no declared permission",
                        "This component is explicitly exported and declares no component-level or application-level permission. Review its intent handling and access controls; exported status alone does not prove an exploitable vulnerability.",
                        f"{tag}: {name} (android:exported=\"true\")",
                        "Restrict export where possible; otherwise enforce caller permissions and validate all incoming intents and data.",
                    )

        # Permissions in the manifest are indicators, not findings of abuse.
        for permission in permissions:
            if permission in SENSITIVE_PERMISSIONS:
                severity, note = SENSITIVE_PERMISSIONS[permission]
                add_finding(
                    severity, "Permissions", "Sensitive permission requested",
                    f"The app declares {permission}. A declared permission does not establish misuse; check whether the feature is necessary and clearly explained to users.",
                    permission,
                    note,
                )

        urls: set[str] = set()
        secret_hits: set[tuple[str, str]] = set()
        crypto_hits: dict[str, tuple[str, str, str]] = {}
        dex_bytes_scanned = 0
        with zipfile.ZipFile(path) as zf:
            for dex_name in dex_names:
                raw = zf.read(dex_name)
                dex_bytes_scanned += len(raw)
                # Search printable sequences rather than executing or decompiling the DEX.
                for match in PRINTABLE_RE.finditer(raw):
                    text_value = match.group(0).decode("utf-8", errors="ignore")
                    for url_match in URL_RE.finditer(match.group(0)):
                        try:
                            raw_url = url_match.group(0).decode("ascii", errors="ignore")
                            cleaned = safe_endpoint(raw_url)
                            if cleaned:
                                urls.add(cleaned)
                        except Exception:
                            pass
                    secret_match = SECRET_RE.search(text_value)
                    if secret_match:
                        secret_hits.add((secret_match.group(1).lower(), masked(secret_match.group(2))))
                    aws_match = AWS_RE.search(text_value)
                    if aws_match:
                        secret_hits.add(("aws access key indicator", masked(aws_match.group(0))))
                    for pattern, title, severity, description in CRYPTO_PATTERNS:
                        match_crypto = pattern.search(text_value)
                        if match_crypto:
                            preview = re.sub(r"[^\x20-\x7e]", "", match_crypto.group(0))[:100]
                            crypto_hits[title] = (severity, description, preview)

        # Reducing duplicates limits alert noise.
        for label, preview in sorted(secret_hits)[:15]:
            add_finding("high", "Code indicators", "Possible hardcoded secret indicator", "A DEX string resembles a credential assignment. This is a heuristic match and may be a false positive; the underlying value is masked in the report.", f"Pattern: {label}; masked value: {preview}", "Verify in the source project. Revoke and rotate any real exposed credential, remove it from client code, and load secrets from a protected server-side service.")

        for title, (severity, description, evidence) in sorted(crypto_hits.items()):
            add_finding(
                severity, "Cryptography", title,
                description + " The scanner found a string or class reference; it did not prove the operation is reachable or used on sensitive data.",
                evidence,
                "Trace the reference to its call site in source/decompiled code, determine whether it protects security-sensitive data, and verify against the current OWASP MASVS/MASTG guidance.",
            )

        url_list = sorted(urls)[:100]
        for endpoint in url_list:
            if endpoint.lower().startswith("http://"):
                add_finding("medium", "Network", "Insecure HTTP endpoint string", "A DEX string references an HTTP URL. Static extraction does not prove the app connects to it or transmits sensitive data.", endpoint, "Use HTTPS for network communication and verify endpoints in context.")

        # Sort highest-severity items first while retaining a stable ID.
        findings.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 99), item["category"], item["title"], item["id"]))
        summary = {sev: sum(1 for item in findings if item["severity"] == sev) for sev in ("critical", "high", "medium", "low", "info")}
        summary["total"] = len(findings)

        # Conservative rule-based correlations. These are review candidates,
        # not verified exploit chains, because static strings cannot prove runtime behavior.
        candidate_paths: list[dict] = []

        def first_matching(predicate):
            return next((item for item in findings if predicate(item)), None)

        cleartext_finding = first_matching(lambda item: item["title"] == "Cleartext traffic is enabled")
        http_finding = first_matching(lambda item: item["title"] == "Insecure HTTP endpoint string")
        if cleartext_finding and http_finding:
            candidate_paths.append({
                "id": "CP-001",
                "title": "Cleartext configuration + HTTP endpoint indicator",
                "severity": "medium",
                "confidence_label": "Review candidate",
                "rule": "HTTP-TRANSPORT-CORRELATION",
                "explanation": "The manifest explicitly permits cleartext traffic and a DEX string contains an HTTP endpoint. Together, these indicators justify reviewing the network path.",
                "steps": [
                    {"finding_id": cleartext_finding["id"], "title": cleartext_finding["title"], "evidence": cleartext_finding["evidence"]},
                    {"finding_id": http_finding["id"], "title": http_finding["title"], "evidence": http_finding["evidence"]},
                ],
                "limitations": "Static evidence does not prove the endpoint is called, that sensitive data is transmitted, or that an attacker can observe traffic.",
                "recommendation": "Trace the endpoint to its call site, review network security configuration and server requirements, and prefer HTTPS.",
            })

        debug_finding = first_matching(lambda item: item["title"] == "Debuggable application build")
        secret_finding = first_matching(lambda item: item["title"] == "Possible hardcoded secret indicator")
        if debug_finding and secret_finding:
            candidate_paths.append({
                "id": "CP-002",
                "title": "Debuggable build + possible hardcoded credential",
                "severity": "high",
                "confidence_label": "Review candidate",
                "rule": "DEBUG-SECRET-CORRELATION",
                "explanation": "A debuggable manifest and a credential-like DEX string occur in the same APK, so verify release-build configuration and whether the string is a real secret.",
                "steps": [
                    {"finding_id": debug_finding["id"], "title": debug_finding["title"], "evidence": debug_finding["evidence"]},
                    {"finding_id": secret_finding["id"], "title": secret_finding["title"], "evidence": secret_finding["evidence"]},
                ],
                "limitations": "The string may be a false positive or a non-sensitive placeholder; a correlation does not prove credential exposure.",
                "recommendation": "Confirm the build variant and inspect the source project. Rotate any verified exposed credential and remove it from client-side code.",
            })

        unprotected_export = first_matching(lambda item: item["title"] == "Exported component has no declared permission")
        sensitive_permission = first_matching(lambda item: item["category"] == "Permissions" and item["severity"] in {"medium", "high"})
        if unprotected_export and sensitive_permission:
            candidate_paths.append({
                "id": "CP-003",
                "title": "Exported component + sensitive-permission footprint",
                "severity": "medium",
                "confidence_label": "Review candidate",
                "rule": "EXPORTED-COMPONENT-CORRELATION",
                "explanation": "The APK has an explicitly exported component without a declared permission and also requests a permission that deserves review. Inspect whether the component can reach sensitive operations.",
                "steps": [
                    {"finding_id": unprotected_export["id"], "title": unprotected_export["title"], "evidence": unprotected_export["evidence"]},
                    {"finding_id": sensitive_permission["id"], "title": sensitive_permission["title"], "evidence": sensitive_permission["evidence"]},
                ],
                "limitations": "The two indicators do not prove that external callers can access the protected data or invoke a sensitive action.",
                "recommendation": "Review the component's intent handling, authorization checks, access to sensitive data, and whether export is required.",
            })

        masvs_assessment = []
        for group in MASVS_GROUPS:
            matched = [item["id"] for item in findings if group in item.get("masvs_groups", [])]
            masvs_assessment.append({
                "group": group,
                "status": "indicators-found" if matched else "no-supported-indicator-found",
                "finding_ids": matched,
                "note": "This is a limited static scan, not a control verification or compliance result.",
            })

        result = {
            "ok": True,
            "schema_version": "1.1",
            "engine": "AppPath Local Static Triage + Androguard",
            "standard_reference": "OWASP MASVS broad group mapping; not a compliance certification",
            "app": {
                "file_name": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "package_name": package_name,
                "version_name": str(version_name),
                "version_code": str(version_code),
                "min_sdk": str(min_sdk),
                "target_sdk": str(target_sdk),
            },
            "permissions": permissions,
            "components": components[:500],
            "urls": url_list,
            "findings": findings,
            "candidate_paths": candidate_paths,
            "summary": summary,
            "masvs_assessment": masvs_assessment,
            "analysis_notes": [
                "This is static triage; the APK was not installed or executed.",
                "Manifest permission requests and string matches are indicators requiring human review, not proof of malicious behavior.",
                "The baseline does not prove exploitability, perform dynamic analysis, or automatically patch APKs.",
                "Candidate paths are conservative static correlations requiring manual validation; they are not verified exploit chains.",
                f"DEX strings scanned: {len(dex_names)} file(s), {dex_bytes_scanned} bytes.",
                "URLs are extracted from DEX strings only, capped at 100 and stripped of query strings.",
                "Cryptography checks are string/class-reference heuristics; they do not prove an algorithm is called or used insecurely.",
                "MASVS labels are broad topic mapping for navigation only. A 'no supported indicator found' result is not a pass or compliance claim.",
                f"Bounded archive checks: {len(infos)} entries; selected DEX scan cap 120 MiB.",
            ],
        }
        print(json.dumps(result, ensure_ascii=False))
        return 0

    except Exception as exc:
        message = str(exc).strip() or exc.__class__.__name__
        print(json.dumps({"ok": False, "error": message}, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
