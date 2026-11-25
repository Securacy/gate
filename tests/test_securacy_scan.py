"""Tests for securacy_scan.py's normalisers: each scanner's real output (run
on a fixture repository, local paths and the fake key scrubbed) turned into
securacy-scan:v1 items. Checkov's and Grype's fixtures are hand-written in
their documented shapes."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import securacy_scan as scan  # noqa: E402

DATA = Path(__file__).resolve().parent / "data" / "scan"
FAKE_SECRET = "FAKE-trufflehog-secret-not-a-real-key-0000"
COMMIT = "d18a867b9466494208e624ce573538b54aabd7d0"
WORKSPACE = Path("/github/workspace")


def load(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def by_purl(items):
    return {i["purl"]: i for i in items}


def test_cyclonedx_components_and_direct_flag():
    comps = by_purl(scan.components_from_cyclonedx(load("syft.cdx.json")))
    lodash = comps["pkg:npm/lodash@4.17.20"]
    assert lodash == {"purl": "pkg:npm/lodash@4.17.20", "name": "lodash", "version": "4.17.20", "ecosystem": "npm",
                      "direct": True, "licenses": ["MIT"], "locations": ["package-lock.json"]}
    assert comps["pkg:npm/stripe@14.0.0"]["direct"] is True
    assert comps["pkg:pypi/pyyaml@5.3"]["direct"] is None
    checkout = comps["pkg:github/actions/checkout@v4"]
    assert sorted(checkout["locations"]) == [".github/workflows/deploy.yml", ".github/workflows/terraform-plan.yml"]
    assert len([c for c in comps if c == "pkg:github/actions/checkout@v4"]) == 1


def test_osv_groups_become_one_vulnerability_each():
    vulns = scan.vulns_from_osv(load("osv.json"))
    lodash = [v for v in vulns if v["purl"] == "pkg:npm/lodash@4.17.20"]
    assert len(lodash) == 4
    cmd_injection = next(v for v in lodash if v["id"] == "GHSA-35jh-r3h4-6jhm")
    assert cmd_injection["aliases"] == ["CVE-2021-23337"]
    assert cmd_injection["severity"] == "high" and cmd_injection["cvss"] == 7.2
    assert cmd_injection["fixed_in"] == ["4.17.21"] and cmd_injection["tools"] == ["osv-scanner"]
    assert all(c.startswith("CWE-") for c in cmd_injection["cwes"])
    pyyaml = [v for v in vulns if v["purl"] == "pkg:pypi/pyyaml@5.3.0"]
    assert {v["id"] for v in pyyaml} == {"GHSA-6757-jp84-gxfx", "GHSA-8q59-q68h-6hv4"}
    assert all(v["severity"] == "critical" for v in pyyaml)


def test_osv_packages_for_the_sbom():
    pkgs = by_purl(scan.osv_components(load("osv.json"), WORKSPACE))
    assert pkgs["pkg:pypi/urllib3@1.23.0"]["locations"] == ["requirements.txt"]
    assert pkgs["pkg:npm/lodash@4.17.20"]["ecosystem"] == "npm"


def test_grype_matches():
    vulns = {v["id"]: v for v in scan.vulns_from_grype(load("grype.json"))}
    assert vulns["GHSA-35jh-r3h4-6jhm"]["aliases"] == ["CVE-2021-23337"]
    assert vulns["GHSA-35jh-r3h4-6jhm"]["cvss"] == 7.2 and vulns["GHSA-35jh-r3h4-6jhm"]["fixed_in"] == ["4.17.21"]
    assert vulns["GHSA-8q59-q68h-6hv4"]["aliases"] == ["CVE-2020-14343"]  # the GHSA alias becomes the id
    assert vulns["MAL-2025-9999"]["malicious"] is True and vulns["MAL-2025-9999"]["severity"] == "low"


def test_osv_and_grype_merge_on_a_shared_id_and_match_syft_purls():
    components = scan.merge_components(scan.components_from_cyclonedx(load("syft.cdx.json")),
                                       scan.osv_components(load("osv.json"), WORKSPACE))
    purls = {c["purl"] for c in components}
    assert "pkg:pypi/pyyaml@5.3" in purls and "pkg:pypi/pyyaml@5.3.0" not in purls  # same version, Syft's purl
    assert "pkg:pypi/urllib3@1.23.0" in purls  # only OSV-Scanner resolved it
    vulns = scan.merge_vulns(components, scan.vulns_from_grype(load("grype.json")),
                             scan.vulns_from_osv(load("osv.json")))
    lodash = next(v for v in vulns if v["id"] == "GHSA-35jh-r3h4-6jhm")
    assert lodash["tools"] == ["grype", "osv-scanner"]
    yaml = next(v for v in vulns if v["id"] == "GHSA-8q59-q68h-6hv4")
    assert yaml["purl"] == "pkg:pypi/pyyaml@5.3" and yaml["severity"] == "critical"
    assert "CVE-2020-14343" in yaml["aliases"] and "PYSEC-2021-142" in yaml["aliases"]
    components = scan.ensure_components(components, vulns)
    assert {"pkg:npm/evil-pkg@1.0.0"} == {c["purl"] for c in components} - purls
    assert all(v["purl"] in {c["purl"] for c in components} for v in vulns)  # every finding's package is in the SBOM


def test_gitleaks_redacted_output_has_no_value():
    items = scan.secrets_from_gitleaks(load("gitleaks.json"), in_tree=False)
    assert items == [{"rule": "stripe-access-token", "detector": "gitleaks", "path": "src/pay.js", "lines": "1",
                      "commit": COMMIT, "verified": None, "in_tree": False}]


def test_trufflehog_raw_fields_are_dropped():
    lines = (DATA / "trufflehog.jsonl").read_text(encoding="utf-8").splitlines()
    assert any(FAKE_SECRET in line for line in lines)  # the fixture still has it
    items = scan.secrets_from_trufflehog(lines, verified_known=False)
    assert FAKE_SECRET not in json.dumps(items) and "fixture@" not in json.dumps(items)
    assert items == [{"rule": "trufflehog-stripe", "detector": "trufflehog", "path": "src/pay.js", "lines": "1",
                      "commit": COMMIT, "verified": None, "in_tree": False}]
    assert scan.secrets_from_trufflehog(lines, verified_known=True)[0]["verified"] is False


def test_trufflehog_result_at_the_same_place_sets_verified_on_the_gitleaks_one():
    gl = scan.secrets_from_gitleaks(load("gitleaks.json"), in_tree=False)
    th = [dict(scan.secrets_from_trufflehog((DATA / "trufflehog.jsonl").read_text().splitlines(),
                                            verified_known=True)[0], verified=True)]
    merged = scan.merge_secrets(gl, th)
    assert len(merged) == 1 and merged[0]["rule"] == "stripe-access-token" and merged[0]["verified"] is True


def test_zizmor_collapses_by_rule_and_path():
    items = scan.workflows_from_zizmor(load("zizmor.json"))
    keys = {(i["rule"], i["path"]) for i in items}
    assert keys == {("artipacked", ".github/workflows/deploy.yml"), ("unpinned-uses", ".github/workflows/deploy.yml"),
                    ("artipacked", ".github/workflows/terraform-plan.yml"),
                    ("dangerous-triggers", ".github/workflows/terraform-plan.yml"),
                    ("unpinned-uses", ".github/workflows/terraform-plan.yml")}
    trigger = next(i for i in items if i["rule"] == "dangerous-triggers")
    assert trigger == {"rule": "dangerous-triggers", "severity": "high", "confidence": "medium",
                       "path": ".github/workflows/terraform-plan.yml", "lines": "4"}
    unpinned = next(i for i in items if i["rule"] == "unpinned-uses" and "deploy" in i["path"])
    assert unpinned["confidence"] == "high" and unpinned["lines"] == "22"


def test_checkov_findings_and_resources():
    findings, resources = scan.iac_from_checkov(load("checkov.json"))
    by_rule = {f["rule"]: f for f in findings}
    assert by_rule["CKV_AWS_20"] == {"rule": "CKV_AWS_20", "severity": "high", "resource": "aws_s3_bucket.invoices",
                                     "path": "terraform/s3.tf", "lines": "1-12",
                                     "title": "S3 Bucket has an ACL defined which allows public READ access."}
    assert by_rule["CKV_AWS_355"]["severity"] == "medium"   # Checkov's own severity wins
    assert by_rule["CKV_AWS_18"]["severity"] == "unknown"   # no severity and not in our short list
    assert by_rule["CKV_K8S_16"]["path"] == "k8s/orders-api.yaml"
    assert sorted((r["type"], r["name"]) for r in resources) == [
        ("aws_iam_policy", "deploy"), ("aws_s3_bucket", "invoices"), ("aws_sqs_queue", "orders")]


def test_checkov_single_report_dict_is_accepted():
    findings, _ = scan.iac_from_checkov(load("checkov.json")[0])
    assert len(findings) == 3


def test_cap_scan_truncates_components_last_and_flags():
    body = {"schema": "securacy-scan:v1", "components": [{"purl": f"pkg:npm/p{i}@1.0.0", "name": f"p{i}",
                                                          "version": "1.0.0", "ecosystem": "npm"} for i in range(500)],
            "vulnerabilities": [], "truncated": False}
    capped = scan.cap_scan(body, max_bytes=5000)
    assert capped["truncated"] is True and 0 < len(capped["components"]) < 500
    assert capped["components"][0]["name"] == "p0"
    assert len(json.dumps(capped)) <= 5000
    assert scan.cap_scan(dict(body, components=body["components"][:3]), max_bytes=5000)["truncated"] is False


def test_bad_items_are_skipped_not_fatal():
    assert scan.components_from_cyclonedx({"components": [{"name": "x"}, "nope", {"purl": "pkg:npm/a@1"}]}) == []
    assert scan.vulns_from_osv({"results": "nope"}) == []
    assert scan.workflows_from_zizmor([{"ident": "x"}]) == []
    assert scan.iac_from_checkov("nope") == ([], [])


def test_osv_items_carry_the_advisorys_summary_when_it_has_one():
    vulns = scan.vulns_from_osv(load("osv.json"))
    cmd_injection = next(v for v in vulns if v["id"] == "GHSA-35jh-r3h4-6jhm")
    assert cmd_injection["summary"] == "Command Injection in lodash"
    assert all(v.get("summary") for v in vulns)  # a PYSEC record has none, but its GHSA alias in the group does
    doc = load("osv.json")
    for result in doc["results"]:
        for pkg in result["packages"]:
            for v in pkg.get("vulnerabilities") or []:
                v.pop("summary", None)
    assert all("summary" not in v for v in scan.vulns_from_osv(doc))


def test_grype_items_carry_the_description_as_summary_and_none_when_it_is_empty():
    vulns = {v["id"]: v for v in scan.vulns_from_grype(load("grype.json"))}
    assert vulns["GHSA-35jh-r3h4-6jhm"]["summary"] == "Command Injection in lodash"
    assert "summary" not in vulns["MAL-2025-9999"]


def test_merging_keeps_osvs_short_summary_over_grypes_long_description():
    lodash = {"purl": "pkg:npm/lodash@4.17.20", "name": "lodash", "version": "4.17.20", "ecosystem": "npm"}
    base = {"id": "GHSA-35jh-r3h4-6jhm", "aliases": [], "purl": lodash["purl"], "severity": "high", "cvss": None,
            "fixed_in": [], "cwes": [], "malicious": False}
    grype = {**base, "tools": ["grype"], "summary": "Lodash versions prior to 4.17.21 are vulnerable to Command "
                                                    "Injection via the template function."}
    osv = {**base, "tools": ["osv-scanner"], "summary": "Command Injection in lodash"}
    assert scan.merge_vulns([lodash], [grype], [osv])[0]["summary"] == "Command Injection in lodash"
    assert scan.merge_vulns([lodash], [grype], [{**osv, "summary": None}])[0]["summary"] == grype["summary"]
    only_osv = scan.merge_vulns([lodash], [{k: v for k, v in grype.items() if k != "summary"}], [osv])
    assert only_osv[0]["summary"] == "Command Injection in lodash"


def test_scanner_text_is_one_short_line_without_hidden_characters():
    assert scan.clean_text("  Two\x0a lines\x09and  spaces ") == "Two lines and spaces"
    assert scan.clean_text("bidi‮ reversed​ zero-width﻿") == "bidi reversed zero-width"
    long = scan.clean_text("word " * 100)
    assert len(long) == 200 and long.endswith("...")
    assert scan.clean_text("") is None and scan.clean_text("​") is None and scan.clean_text(42) is None
