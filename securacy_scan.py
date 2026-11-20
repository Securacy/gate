"""The supply-chain scan: open-source scanners run in this job, their output
turned into one small `securacy-scan:v1` document for Securacy.

What leaves the runner: package URLs, versions, licenses and manifest paths;
advisory ids; rule ids with file, line and commit for secrets, workflow and
IaC findings. Never code, and never a secret's value: Gitleaks runs with
--redact, and TruffleHog's raw fields are dropped while its output is read.

Normalisers here are pure functions over each tool's JSON, so they are tested
on real outputs (tests/data/scan). Standard library only, Python 3.8+.
"""

import json
import os
import re
import shutil
import subprocess  # nosec B404
import time
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple

import securacy_tools

SCHEMA = "securacy-scan:v1"
PURL_TYPES = ("npm", "pypi", "maven", "golang", "cargo", "gem", "nuget", "composer", "pub", "swift", "hex",
              "deb", "apk", "rpm", "github")
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
LIMITS = {"components": 10000, "vulnerabilities": 2000, "secrets": 500, "workflows": 500, "iac": 1000,
          "iac_resources": 1000}
MAX_SCAN_BYTES = 4 * 1024 * 1024
# Checkov's open-source output often has no severity. These are the checks we
# rate ourselves because their meaning is unambiguous (public data, admin
# rights, open admin ports, privileged containers).
CHECKOV_SEVERITY = {"CKV_AWS_20": "high", "CKV_AWS_57": "high", "CKV_AWS_17": "high", "CKV_AWS_1": "high",
                    "CKV_AWS_62": "high", "CKV_AWS_63": "high", "CKV_AWS_24": "high", "CKV_AWS_25": "high",
                    "CKV_K8S_16": "high"}

_PATH = re.compile(r"^(?!/)(?!.*//)(?!.*(?:^|/)\.{1,2}(?:/|$))[A-Za-z0-9_.@+/-]{1,300}$")
_PURL = re.compile(r"^pkg:(?:" + "|".join(PURL_TYPES) + r")/[A-Za-z0-9%@._+/:~?=&,-]{1,290}$")
_NAME = re.compile(r"^[A-Za-z0-9@._+/:~-]{1,214}$")
_VERSION = re.compile(r"^[A-Za-z0-9._+:~^-]{1,100}$")
_LICENSE = re.compile(r"^[A-Za-z0-9.+:() -]{1,64}$")
_ADVISORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,63}$")
_CWE = re.compile(r"^CWE-\d{1,5}$")
_RULE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
_RESOURCE = re.compile(r"^[A-Za-z0-9_.\[\]:/-]{1,200}$")
_SHA = re.compile(r"^[0-9a-f]{7,64}$")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _ok(pattern: "re.Pattern[str]", value: Any) -> bool:
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def clean_path(raw: Any, workspace: Optional[PurePosixPath] = None) -> Optional[str]:
    """A repository-relative path with "/" separators, or None."""
    if not isinstance(raw, str) or not raw:
        return None
    path = raw.replace("\\", "/")
    if workspace is not None:
        prefix = str(workspace).replace("\\", "/").rstrip("/") + "/"
        if path.startswith(prefix):
            path = path[len(prefix):]
        elif path.startswith("/") or re.match(r"^[A-Za-z]:/", path):
            return None  # outside the checkout
    while path.startswith("./"):
        path = path[2:]
    path = path.lstrip("/")
    return path if _PATH.fullmatch(path) else None


def strip_purl(purl: str) -> str:
    return purl.split("#", 1)[0].split("?", 1)[0]


def _purl_parts(purl: str) -> Tuple[str, str, str]:
    """(type, name, version) of a package URL."""
    body = strip_purl(purl)[4:]
    ptype, _, rest = body.partition("/")
    name, _, version = rest.rpartition("@")
    return ptype, name, version


def _norm_name(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower() if ecosystem in ("npm", "github") else name


def _same_version(ecosystem: str, a: str, b: str) -> bool:
    if a == b:
        return True
    if ecosystem == "pypi" and re.fullmatch(r"\d+(\.\d+)*", a or "") and re.fullmatch(r"\d+(\.\d+)*", b or ""):
        ta, tb = [int(x) for x in a.split(".")], [int(x) for x in b.split(".")]
        while ta and ta[-1] == 0:
            ta.pop()
        while tb and tb[-1] == 0:
            tb.pop()
        return ta == tb
    return False


def _band(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low" if score > 0 else "unknown"


def _canonical(ids: Iterable[str]) -> Tuple[str, List[str]]:
    """The id to show (a GHSA when there is one, else a CVE, else the first) and the rest as aliases."""
    unique: List[str] = []
    for i in ids:
        if _ok(_ADVISORY, i) and i not in unique:
            unique.append(i)
    if not unique:
        return "", []
    main = next((i for i in unique if i.startswith("GHSA-")), None) or \
        next((i for i in unique if i.startswith("CVE-")), None) or unique[0]
    return main, [i for i in unique if i != main]


def _lines(start: Any, end: Any = None) -> str:
    a = start if isinstance(start, int) and start > 0 else 1
    b = end if isinstance(end, int) and end > a else None
    return f"{a}-{b}" if b else str(a)


# ---------------------------------------------------------------------------
# SBOM
# ---------------------------------------------------------------------------

def _licenses(raw: Any) -> List[str]:
    out: List[str] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        lic = item.get("license") if isinstance(item.get("license"), dict) else {}
        value = item.get("expression") or lic.get("id") or lic.get("name")
        if _ok(_LICENSE, value) and value not in out:
            out.append(value)
    return out[:5]


def components_from_cyclonedx(doc: Any) -> List[Dict[str, Any]]:
    """Syft's CycloneDX: one item per package URL, locations merged, `direct`
    from the dependency graph (depended on by a top-level package)."""
    if not isinstance(doc, dict):
        return []
    by_ref: Dict[str, str] = {}
    out: Dict[str, Dict[str, Any]] = {}
    for c in doc.get("components") or []:
        if not isinstance(c, dict):
            continue
        purl, name, version = c.get("purl"), c.get("name"), c.get("version")
        if not (_ok(_PURL, purl) and isinstance(name, str) and _ok(_VERSION, version)):
            continue
        name = f"{c['group']}:{name}" if isinstance(c.get("group"), str) and c["group"] else name
        if not _NAME.fullmatch(name):
            continue
        by_ref[str(c.get("bom-ref") or purl)] = purl
        locations = [clean_path(p.get("value")) for p in c.get("properties") or []
                     if isinstance(p, dict) and str(p.get("name", "")).startswith("syft:location:")
                     and str(p.get("name", "")).endswith(":path")]
        item = out.setdefault(purl, {"purl": purl, "name": name, "version": version,
                                     "ecosystem": _purl_parts(purl)[0], "direct": None,
                                     "licenses": _licenses(c.get("licenses")), "locations": []})
        for loc in locations:
            if loc and loc not in item["locations"] and len(item["locations"]) < 5:
                item["locations"].append(loc)
    deps = [d for d in doc.get("dependencies") or [] if isinstance(d, dict)]
    depended = {by_ref.get(r) for d in deps for r in d.get("dependsOn") or []}
    roots = [d for d in deps if by_ref.get(d.get("ref")) not in depended and d.get("dependsOn")]
    direct = {by_ref.get(r) for d in roots for r in d.get("dependsOn") or []}
    for purl, item in out.items():
        if purl in direct:
            item["direct"] = True
        elif purl in depended:
            item["direct"] = False
    return list(out.values())


def osv_components(doc: Any, workspace: PurePosixPath) -> List[Dict[str, Any]]:
    """The packages OSV-Scanner found (it resolves some transitive ones Syft doesn't list)."""
    out: Dict[str, Dict[str, Any]] = {}
    for result in (doc.get("results") if isinstance(doc, dict) else None) or []:
        if not isinstance(result, dict):
            continue
        location = clean_path((result.get("source") or {}).get("path"), workspace)
        for pkg in result.get("packages") or []:
            info = (pkg or {}).get("package") or {}
            purl = info.get("purl")
            if not isinstance(purl, str) or not _ok(_PURL, strip_purl(purl)):
                continue
            purl = strip_purl(purl)
            ptype, name, version = _purl_parts(purl)
            if not (_NAME.fullmatch(name or "") and _ok(_VERSION, version)):
                continue
            item = out.setdefault(purl, {"purl": purl, "name": name, "version": version, "ecosystem": ptype,
                                         "direct": None, "licenses": [], "locations": []})
            if location and location not in item["locations"]:
                item["locations"].append(location)
    return list(out.values())


def _find(components: List[Dict[str, Any]], purl: str) -> Optional[Dict[str, Any]]:
    bare = strip_purl(purl)
    ptype, name, version = _purl_parts(bare)
    for c in components:
        if strip_purl(c["purl"]) == bare:
            return c
    for c in components:
        cp = _purl_parts(c["purl"])
        if cp[0] == ptype and _norm_name(ptype, cp[1]) == _norm_name(ptype, name) and \
                _same_version(ptype, cp[2], version):
            return c
    return None


def merge_components(syft: List[Dict[str, Any]], extra: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Syft's list, plus packages only another tool found. The same package
    and version (PEP 503 names, 5.3 == 5.3.0) keeps Syft's package URL."""
    out = [dict(c, locations=list(c["locations"])) for c in syft]
    for c in extra:
        match = _find(out, c["purl"])
        if match is None:
            out.append(dict(c, locations=list(c["locations"])))
        else:
            for loc in c["locations"]:
                if loc not in match["locations"] and len(match["locations"]) < 5:
                    match["locations"].append(loc)
    return out


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------

def vulns_from_grype(doc: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for m in (doc.get("matches") if isinstance(doc, dict) else None) or []:
        if not isinstance(m, dict):
            continue
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        main, aliases = _canonical([v.get("id")] + [r.get("id") for r in m.get("relatedVulnerabilities") or []
                                                    if isinstance(r, dict)])
        purl = a.get("purl")
        if not main or not _ok(_PURL, purl):
            continue
        scores = [((c.get("metrics") or {}).get("baseScore")) for c in v.get("cvss") or [] if isinstance(c, dict)]
        scores = [float(s) for s in scores if isinstance(s, (int, float)) and 0 <= s <= 10]
        severity = str(v.get("severity") or "unknown").lower()
        severity = {"negligible": "low", "moderate": "medium"}.get(severity, severity)
        fixed = [f for f in (v.get("fix") or {}).get("versions") or [] if _ok(_VERSION, f)]
        out.append({"id": main, "aliases": aliases[:20], "purl": purl,
                    "severity": severity if severity in SEVERITY_RANK else "unknown",
                    "cvss": max(scores) if scores else None, "fixed_in": fixed[:10], "cwes": [],
                    "malicious": any(i.startswith("MAL-") for i in [main] + aliases), "tools": ["grype"]})
    return out


def _osv_fixed(vulns: List[Dict[str, Any]], ecosystem: str, name: str) -> List[str]:
    fixed: List[str] = []
    for v in vulns:
        for affected in v.get("affected") or []:
            pkg = (affected or {}).get("package") or {}
            if _norm_name(ecosystem, str(pkg.get("name") or "")) != _norm_name(ecosystem, name):
                continue
            for r in affected.get("ranges") or []:
                for event in (r or {}).get("events") or []:
                    value = (event or {}).get("fixed")
                    if _ok(_VERSION, value) and value not in fixed:
                        fixed.append(value)
    return fixed[:10]


def vulns_from_osv(doc: Any) -> List[Dict[str, Any]]:
    """One item per OSV-Scanner group (its ids are the same issue under several databases)."""
    out: List[Dict[str, Any]] = []
    for result in (doc.get("results") if isinstance(doc, dict) else None) or []:
        if not isinstance(result, dict):
            continue
        for pkg in result.get("packages") or []:
            info = (pkg or {}).get("package") or {}
            purl = strip_purl(str(info.get("purl") or ""))
            if not _ok(_PURL, purl):
                continue
            ecosystem, name, _ = _purl_parts(purl)
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities") or [] if isinstance(v, dict)}
            groups = pkg.get("groups") or [{"ids": [i], "aliases": (vulns[i].get("aliases") or [])} for i in vulns]
            for group in groups:
                members = [vulns[i] for i in group.get("ids") or [] if i in vulns]
                ids = list(group.get("ids") or []) + list(group.get("aliases") or [])
                for v in members:
                    ids += list(v.get("aliases") or [])
                main, aliases = _canonical(ids)
                if not main:
                    continue
                try:
                    score: Optional[float] = float(group.get("max_severity") or "")
                except ValueError:
                    score = None
                severity = _band(score)
                if severity == "unknown":
                    db = {str((v.get("database_specific") or {}).get("severity") or "").lower() for v in members}
                    severity = next((s for s in ("critical", "high", "medium", "low") if s in db or
                                     (s == "medium" and "moderate" in db)), "unknown")
                cwes: List[str] = []
                for v in members:
                    for c in (v.get("database_specific") or {}).get("cwe_ids") or []:
                        if _ok(_CWE, c) and c not in cwes:
                            cwes.append(c)
                out.append({"id": main, "aliases": aliases[:20], "purl": purl, "severity": severity,
                            "cvss": score if score is not None and 0 <= score <= 10 else None,
                            "fixed_in": _osv_fixed(members, ecosystem, name), "cwes": cwes[:10],
                            "malicious": any(i.startswith("MAL-") for i in [main] + aliases),
                            "tools": ["osv-scanner"]})
    return out


def merge_vulns(components: List[Dict[str, Any]], *lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One item per package and issue: two tools' items for the same package
    that share any id merge (aliases, fixes, CWEs and tools unioned, the
    higher severity kept). Each package URL is the SBOM's for that package."""
    merged: List[Dict[str, Any]] = []
    for items in lists:
        for raw in items:
            item = dict(raw)
            match = _find(components, item["purl"])
            if match:
                item["purl"] = match["purl"]
            ids = {item["id"], *item["aliases"]}
            same = next((m for m in merged if strip_purl(m["purl"]) == strip_purl(item["purl"])
                         and ids & {m["id"], *m["aliases"]}), None)
            if same is None:
                merged.append(item)
                continue
            main, aliases = _canonical([same["id"], item["id"], *same["aliases"], *item["aliases"]])
            same["id"], same["aliases"] = main, aliases[:20]
            if SEVERITY_RANK[item["severity"]] > SEVERITY_RANK[same["severity"]]:
                same["severity"] = item["severity"]
            scores = [s for s in (same["cvss"], item["cvss"]) if s is not None]
            same["cvss"] = max(scores) if scores else None
            for key, limit in (("fixed_in", 10), ("cwes", 10), ("tools", 5)):
                for value in item[key]:
                    if value not in same[key] and len(same[key]) < limit:
                        same[key].append(value)
            same["malicious"] = same["malicious"] or item["malicious"]
    for item in merged:
        item["tools"] = sorted(item["tools"])
    return merged


def ensure_components(components: List[Dict[str, Any]], vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Every vulnerable package is in the SBOM, so Securacy can tell whether a change added it."""
    out = list(components)
    known = {strip_purl(c["purl"]) for c in out}
    for v in vulns:
        bare = strip_purl(v["purl"])
        if bare in known:
            continue
        ptype, name, version = _purl_parts(bare)
        if _NAME.fullmatch(name or "") and _ok(_VERSION, version):
            out.append({"purl": v["purl"], "name": name, "version": version, "ecosystem": ptype, "direct": None,
                        "licenses": [], "locations": []})
            known.add(bare)
    return out


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

def secrets_from_gitleaks(items: Any, *, in_tree: bool) -> List[Dict[str, Any]]:
    """Gitleaks run with --redact. Only rule, place and commit are read."""
    out: List[Dict[str, Any]] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        rule, path, commit = item.get("RuleID"), clean_path(item.get("File")), item.get("Commit") or None
        if not (_ok(_RULE, rule) and path) or (commit is not None and not _ok(_SHA, commit)):
            continue
        out.append({"rule": rule, "detector": "gitleaks", "path": path,
                    "lines": _lines(item.get("StartLine"), item.get("EndLine")), "commit": commit,
                    "verified": None, "in_tree": in_tree})
    return out


def secrets_from_trufflehog(lines: Iterable[str], *, verified_known: bool) -> List[Dict[str, Any]]:
    """TruffleHog JSON lines. Its records carry the raw secret and the
    author's email; only the detector, the verified flag and the place are
    read, so nothing else ever leaves this function."""
    out: List[Dict[str, Any]] = []
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        detector = re.sub(r"[^a-z0-9]+", "-", str(record.get("DetectorName") or "").lower()).strip("-")[:60]
        data = ((record.get("SourceMetadata") or {}).get("Data") or {})
        source = data.get("Git") or data.get("Filesystem") or {}
        path = clean_path(source.get("file"))
        commit = source.get("commit") or None
        if not detector or not path or (commit is not None and not _ok(_SHA, commit)):
            continue
        out.append({"rule": f"trufflehog-{detector}", "detector": "trufflehog", "path": path,
                    "lines": _lines(source.get("line")), "commit": commit,
                    "verified": bool(record.get("Verified")) if verified_known else None,
                    "in_tree": "Filesystem" in data})
    return out


def merge_secrets(gitleaks: List[Dict[str, Any]], trufflehog: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """A TruffleHog result at a place Gitleaks already reported only adds whether it was verified."""
    out = [dict(s) for s in gitleaks]
    for th in trufflehog:
        same = next((s for s in out if (s["path"], s["lines"], s["commit"]) == (th["path"], th["lines"], th["commit"])),
                    None)
        if same is None:
            out.append(dict(th))
        elif th["verified"] is not None:
            same["verified"] = th["verified"] or bool(same["verified"])
    return out


# ---------------------------------------------------------------------------
# Workflows and IaC
# ---------------------------------------------------------------------------

def _zizmor_level(value: Any) -> str:
    text = str(value or "").lower()
    return {"informational": "low", "info": "low"}.get(text, text if text in SEVERITY_RANK else "unknown")


def workflows_from_zizmor(doc: Any) -> List[Dict[str, Any]]:
    found: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for f in doc if isinstance(doc, list) else []:
        if not isinstance(f, dict) or f.get("ignored"):
            continue
        rule = f.get("ident")
        primary = next((loc for loc in f.get("locations") or [] if isinstance(loc, dict)
                        and (loc.get("symbolic") or {}).get("kind") == "Primary"), None)
        if not _ok(_RULE, rule) or primary is None:
            continue
        key = (primary.get("symbolic") or {}).get("key") or {}
        local = key.get("Local") if isinstance(key, dict) else None
        path = clean_path((local or {}).get("given_path") or (local or {}).get("verbatim_path"))
        span = ((primary.get("concrete") or {}).get("location") or {})
        start = (span.get("start_point") or {}).get("row")
        end = (span.get("end_point") or {}).get("row")
        if not path or not isinstance(start, int):
            continue
        det = f.get("determinations") or {}
        severity, confidence = _zizmor_level(det.get("severity")), _zizmor_level(det.get("confidence"))
        confidence = confidence if confidence in ("high", "medium", "low") else "unknown"
        item = {"rule": rule, "severity": severity, "confidence": confidence, "path": path,
                "lines": _lines(start + 1, end + 1 if isinstance(end, int) else None)}
        current = found.get((rule, path))
        if current is None:
            found[(rule, path)] = item
        else:
            if SEVERITY_RANK[severity] > SEVERITY_RANK[current["severity"]]:
                current["severity"] = severity
            if SEVERITY_RANK.get(confidence, 0) > SEVERITY_RANK.get(current["confidence"], 0):
                current["confidence"] = confidence
    return sorted(found.values(), key=lambda i: (i["path"], int(i["lines"].split("-")[0]), i["rule"]))


def _checkov_path(check: Dict[str, Any]) -> Optional[str]:
    absolute = str(check.get("file_abs_path") or "")
    if absolute.startswith("/src/"):
        return clean_path(absolute[len("/src/"):])
    return clean_path(check.get("file_path"))


def iac_from_checkov(doc: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    reports = doc if isinstance(doc, list) else [doc] if isinstance(doc, dict) else []
    findings: List[Dict[str, Any]] = []
    resources: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for report in reports:
        if not isinstance(report, dict):
            continue
        results = report.get("results") or {}
        terraform = report.get("check_type") == "terraform"
        for state in ("failed_checks", "passed_checks"):
            for check in results.get(state) or []:
                if not isinstance(check, dict):
                    continue
                path, resource, rule = _checkov_path(check), check.get("resource"), check.get("check_id")
                span = check.get("file_line_range") or [1, 1]
                lines = _lines(span[0] if span else 1, span[1] if len(span) > 1 else None)
                if not path or not _ok(_RESOURCE, resource):
                    continue
                if state == "failed_checks" and _ok(_RULE, rule):
                    severity = str(check.get("severity") or CHECKOV_SEVERITY.get(rule) or "unknown").lower()
                    findings.append({"rule": rule, "severity": severity if severity in SEVERITY_RANK else "unknown",
                                     "resource": resource, "path": path, "lines": lines})
                parts = resource.split(".")
                if terraform and len(parts) >= 2 and parts[0] != "data":
                    rtype, name = parts[-2], re.sub(r"\[.*\]$", "", parts[-1])
                    if _ok(_RULE, rtype) and _ok(_RESOURCE, name):
                        resources.setdefault((rtype, name, path), {"type": rtype, "name": name, "path": path,
                                                                   "lines": lines})
    return findings, list(resources.values())


# ---------------------------------------------------------------------------
# Size
# ---------------------------------------------------------------------------

def cap_scan(scan: Dict[str, Any], max_bytes: int = MAX_SCAN_BYTES) -> Dict[str, Any]:
    """Keep the document under max_bytes: lists are cut to their limits, then
    components are dropped from the end until it fits. `truncated` says so."""
    out = dict(scan)
    truncated = bool(out.get("truncated"))
    for key, limit in LIMITS.items():
        items = out.get(key)
        if isinstance(items, list) and len(items) > limit:
            out[key], truncated = items[:limit], True
    components = list(out.get("components") or [])
    out["components"], out["truncated"] = components, truncated
    while len(json.dumps(out)) > max_bytes and components:
        components = components[: max(0, len(components) - max(1, len(components) // 10))]
        out["components"], out["truncated"] = components, True
    return out


# ---------------------------------------------------------------------------
# Running the scanners
# ---------------------------------------------------------------------------

PER_TOOL_SECONDS = 240
HISTORY_SECONDS = 300
ZERO_SHA = "0" * 40
TOOL_NAMES = ("syft", "grype", "osv-scanner", "gitleaks", "trufflehog", "zizmor", "checkov")
_SKIP_DIRS = {".git", "node_modules", "vendor", ".terraform", ".venv", "venv", "dist", "build"}
_MAX_WALK = 20000


class ScanOptions:
    def __init__(self, enabled: bool = True, verify_secrets: bool = False, osv_offline: bool = False,
                 timeout_s: int = 600) -> None:
        self.enabled, self.verify_secrets, self.osv_offline, self.timeout_s = \
            enabled, verify_secrets, osv_offline, timeout_s


class ScanResult:
    def __init__(self, doc: Optional[Dict[str, Any]], notices: List[str], sbom_path: Optional[Path]) -> None:
        self.doc, self.notices, self.sbom_path = doc, notices, sbom_path


def _has_iac(workspace: Path) -> bool:
    """Terraform, a Dockerfile, a Kubernetes manifest or a CloudFormation template."""
    seen = 0
    for root, dirs, files in os.walk(str(workspace)):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not (d == ".github" and root == str(workspace))]
        for name in files:
            seen += 1
            if seen > _MAX_WALK:
                return False
            if name.endswith((".tf", ".tf.json")) or name == "Dockerfile" or name.startswith("Dockerfile."):
                return True
            if name.endswith((".yaml", ".yml")):
                try:
                    with open(os.path.join(root, name), "r", encoding="utf-8", errors="replace") as handle:
                        head = handle.read(4096)
                except OSError:
                    continue
                if ("apiVersion:" in head and "kind:" in head) or "AWSTemplateFormatVersion" in head:
                    return True
    return False


def secret_scope(event_name: str, event: Dict[str, Any], has_scan: bool) -> Tuple[str, Optional[str], Optional[str]]:
    """(scope, base, head) for the secret scan: this PR's commits, the pushed
    commits, the working tree, or (a repository's first scan) all of history."""
    if event_name == "pull_request":
        pr = event.get("pull_request") or {}
        base, head = (pr.get("base") or {}).get("sha"), (pr.get("head") or {}).get("sha")
        if _ok(_SHA, base) and _ok(_SHA, head):
            return "change", base, head
    elif event_name == "push":
        before, after = event.get("before"), event.get("after")
        if _ok(_SHA, before) and _ok(_SHA, after) and before != ZERO_SHA:
            return "push", before, after
        return "tree", None, None
    return ("tree" if has_scan else "history"), None, None


def gitleaks_argv(binary: Path, scope: str, base: Optional[str], head: Optional[str], report: Path) -> List[str]:
    common = ["--redact", "--no-banner", "--report-format", "json", "--report-path", str(report), "--exit-code", "0"]
    if scope == "tree":
        return [str(binary), "dir"] + common + ["."]
    if scope == "history":
        return [str(binary), "git"] + common + ["."]
    return [str(binary), "git"] + common + [f"--log-opts={base}..{head}", "."]


def trufflehog_argv(binary: Path, scope: str, base: Optional[str]) -> List[str]:
    if scope == "tree":
        return [str(binary), "filesystem", ".", "--json", "--no-update"]
    argv = [str(binary), "git", "file://.", "--json", "--no-update"]
    return argv + (["--since-commit", base] if scope in ("change", "push") and base else [])


def osv_argv(binary: Path, offline: bool) -> List[str]:
    argv = [str(binary), "scan", "source", "-r", "--format", "json", "--allow-no-lockfiles"]
    if offline:  # no package name leaves the runner: local databases and no transitive resolution
        argv += ["--offline-vulnerabilities", "--download-offline-databases", "--no-resolve"]
    return argv + ["."]


def checkov_argv(docker: str, image: str, workspace: Path) -> List[str]:
    return [docker, "run", "--rm", "--network", "none", "-v", f"{workspace}:/src:ro", image,
            "-d", "/src", "-o", "json", "--soft-fail", "--skip-download",
            "--framework", "terraform,kubernetes,dockerfile,cloudformation"]


class _Runner:
    """One scan's bookkeeping: tool status, the shared deadline, notices."""

    def __init__(self, workspace: Path, lock: Dict[str, Any], tools_dir: Path, runner: Any, fetch: Any,
                 env: Dict[str, str], timeout_s: int) -> None:
        self.workspace, self.lock, self.tools_dir = workspace, lock, tools_dir
        self.runner, self.fetch, self.env = runner, fetch, env
        self.deadline = time.monotonic() + max(60, timeout_s)
        self.notices: List[str] = []
        self.status = {name: {"version": str((lock.get(name) or {}).get("version") or ""), "status": "skipped",
                              "seconds": 0} for name in TOOL_NAMES}

    def binary(self, name: str) -> Optional[Path]:
        result = self.fetch(name, self.lock, self.tools_dir)
        self.status[name]["status"] = result.status
        if result.status != "ok":
            self.notices.append(f"{name} was not run: its download was {result.status}.")
        return result.path if result.status == "ok" else None

    def call(self, name: str, argv: List[str], ok_codes: Tuple[int, ...] = (0,), limit: int = PER_TOOL_SECONDS,
             extra_env: Optional[Dict[str, str]] = None) -> Optional[bytes]:
        remaining = self.deadline - time.monotonic()
        if remaining < 5:
            self.status[name]["status"] = "timeout"
            self.notices.append(f"{name} was not run: the scan ran out of time.")
            return None
        started = time.monotonic()
        try:
            proc = self.runner(argv, cwd=str(self.workspace), env=dict(self.env, **(extra_env or {})),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=min(limit, remaining))
        except subprocess.TimeoutExpired:
            self.status[name]["status"] = "timeout"
            self.notices.append(f"{name} timed out.")
            return None
        except OSError as error:
            self.status[name]["status"] = "failed"
            self.notices.append(f"{name} could not start ({type(error).__name__}).")
            return None
        self.status[name]["seconds"] = int(time.monotonic() - started)
        if proc.returncode not in ok_codes:
            self.status[name]["status"] = "failed"
            self.notices.append(f"{name} failed (exit {proc.returncode}).")
            return None
        self.status[name]["status"] = "ok"
        return proc.stdout or b""

    def parse(self, name: str, raw: Optional[bytes]) -> Any:
        if raw is None:
            return None
        try:
            return json.loads(raw.decode("utf-8", "replace") or "null")
        except ValueError:
            self.status[name]["status"] = "failed"
            self.notices.append(f"{name} output could not be read.")
            return None

    def commit_exists(self, sha: str) -> bool:
        proc = self.runner(["git", "cat-file", "-e", sha + "^{commit}"], cwd=str(self.workspace), env=self.env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        return proc.returncode == 0


def _dependencies(run: _Runner, workspace: Path, sbom: Path, offline: bool) -> Tuple[list, list]:
    components: List[Dict[str, Any]] = []
    grype_vulns: List[Dict[str, Any]] = []
    syft = run.binary("syft")
    if syft and run.call("syft", [str(syft), "scan", "dir:.", "-o", f"cyclonedx-json={sbom}", "-q"]) is not None:
        try:
            components = components_from_cyclonedx(json.loads(sbom.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            run.status["syft"]["status"] = "failed"
            run.notices.append("The SBOM Syft wrote could not be read.")
    if run.status["syft"]["status"] == "ok":
        grype = run.binary("grype")
        if grype:
            env = {"GRYPE_DB_CACHE_DIR": str(run.tools_dir / "grype-db"), "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
            grype_vulns = vulns_from_grype(run.parse("grype", run.call(
                "grype", [str(grype), f"sbom:{sbom}", "-o", "json", "-q"], extra_env=env)))
    osv_doc = None
    osv = run.binary("osv-scanner")
    if osv:
        osv_doc = run.parse("osv-scanner", run.call("osv-scanner", osv_argv(osv, offline), ok_codes=(0, 1, 128)))
    extra = osv_components(osv_doc, PurePosixPath(str(workspace).replace("\\", "/"))) if osv_doc else []
    components = merge_components(components, extra)
    vulns = merge_vulns(components, grype_vulns, vulns_from_osv(osv_doc) if osv_doc else [])
    return ensure_components(components, vulns), vulns


def _secrets(run: _Runner, out_dir: Path, scope: str, base: Optional[str], head: Optional[str],
             verify: bool) -> list:
    secrets: List[Dict[str, Any]] = []
    gitleaks = run.binary("gitleaks")
    if gitleaks:
        report = out_dir / "gitleaks.json"
        limit = HISTORY_SECONDS if scope == "history" else PER_TOOL_SECONDS
        if run.call("gitleaks", gitleaks_argv(gitleaks, scope, base, head, report), limit=limit) is not None:
            try:
                secrets = secrets_from_gitleaks(json.loads(report.read_text(encoding="utf-8") or "[]"),
                                                in_tree=scope == "tree")
            except (OSError, ValueError):
                run.status["gitleaks"]["status"] = "failed"
        if report.exists():
            report.unlink()
    if verify:
        truffle = run.binary("trufflehog")
        raw = run.call("trufflehog", trufflehog_argv(truffle, scope, base)) if truffle else None
        if raw is not None:
            found = secrets_from_trufflehog(raw.decode("utf-8", "replace").splitlines(), verified_known=True)
            secrets = merge_secrets(secrets, found)
    return secrets


def run_scan(workspace: Path, event_name: str, event: Dict[str, Any], options: ScanOptions, *, has_scan: bool,
             out_dir: Path, artifacts_dir: Path, tools_dir: Path, runner: Any = subprocess.run,
             fetch: Any = securacy_tools.fetch_tool, docker: Optional[str] = "auto",
             environ: Optional[Dict[str, str]] = None, lock: Optional[Dict[str, Any]] = None) -> ScanResult:
    """Run every scanner that applies, each on its own: one failing never
    stops the others. Writes out_dir/scan.json and artifacts_dir/sbom.cdx.json."""
    if not options.enabled:
        return ScanResult(None, [], None)
    lock = lock if lock is not None else securacy_tools.load_lock()
    docker = shutil.which("docker") if docker == "auto" else docker
    for d in (out_dir, artifacts_dir, tools_dir):
        d.mkdir(parents=True, exist_ok=True)
    run = _Runner(workspace, lock, tools_dir, runner, fetch, securacy_tools.clean_env(environ), options.timeout_s)

    sbom = artifacts_dir / "sbom.cdx.json"
    components, vulns = _dependencies(run, workspace, sbom, options.osv_offline)

    scope, base, head = secret_scope(event_name, event, has_scan)
    if base and head and not (run.commit_exists(base) and run.commit_exists(head)):
        run.notices.append("The change's commits are not all in this checkout (a force push or a shallow clone), "
                           "so the secret scan did a full sweep of the working tree instead.")
        scope, base, head = "tree", None, None
    secrets = _secrets(run, out_dir, scope, base, head, options.verify_secrets)

    workflows: List[Dict[str, Any]] = []
    if (workspace / ".github" / "workflows").is_dir():
        zizmor = run.binary("zizmor")
        if zizmor:
            workflows = workflows_from_zizmor(run.parse("zizmor", run.call(
                "zizmor", [str(zizmor), "--format", "json", "--offline", ".github/workflows"],
                ok_codes=(0, 10, 11, 12, 13, 14))))
    iac: List[Dict[str, Any]] = []
    resources: List[Dict[str, Any]] = []
    if _has_iac(workspace):
        if not docker:
            run.notices.append("Checkov was not run: Docker is not available on this runner.")
        else:
            image = str((lock.get("checkov") or {}).get("image") or "")
            iac, resources = iac_from_checkov(run.parse("checkov", run.call(
                "checkov", checkov_argv(docker, image, workspace), ok_codes=(0, 1))))

    doc = cap_scan({"schema": SCHEMA, "tools": run.status, "secrets_scope": scope, "components": components,
                    "vulnerabilities": vulns, "secrets": secrets, "workflows": workflows, "iac": iac,
                    "iac_resources": resources, "truncated": False})
    (out_dir / "scan.json").write_text(json.dumps(doc), encoding="utf-8")
    return ScanResult(doc, run.notices, sbom if sbom.is_file() else None)
