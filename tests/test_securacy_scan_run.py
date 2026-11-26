"""Tests for securacy_scan.run_scan and the action's scan step. No network
and no real scanners: a fake runner replays the recorded outputs."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import securacy_ci as ci  # noqa: E402
import securacy_scan as scan  # noqa: E402
import securacy_tools as tools  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "data" / "scan"
FAKE_SECRET = "FAKE-trufflehog-secret-not-a-real-key-0000"
BASE, HEAD = "a" * 40, "b" * 40
PR_EVENT = {"pull_request": {"number": 7, "base": {"sha": BASE}, "head": {"sha": HEAD}}}


class FakeRunner:
    """Answers each scanner call with the recorded output; records every call."""

    def __init__(self, fail=(), git_ok=True):
        self.calls, self.fail, self.git_ok = [], set(fail), git_ok

    def __call__(self, argv, cwd=None, env=None, stdout=None, stderr=None, timeout=None):
        self.calls.append({"argv": list(argv), "env": dict(env or {}), "cwd": cwd})
        name = Path(argv[0]).name
        if name == "git":
            return subprocess.CompletedProcess(argv, 0 if self.git_ok else 128, b"", b"")
        if name in self.fail:
            return subprocess.CompletedProcess(argv, 2, b"", b"boom")
        out = b""
        if name == "syft":
            target = next(a for a in argv if a.startswith("cyclonedx-json=")).split("=", 1)[1]
            Path(target).write_bytes((DATA / "syft.cdx.json").read_bytes())
        elif name == "grype":
            out = (DATA / "grype.json").read_bytes()
        elif name == "osv-scanner":
            out, code = (DATA / "osv.json").read_bytes(), 1  # 1: vulnerabilities found
            return subprocess.CompletedProcess(argv, code, out, b"")
        elif name == "gitleaks":
            report = argv[argv.index("--report-path") + 1]
            Path(report).write_bytes((DATA / "gitleaks.json").read_bytes())
        elif name == "trufflehog":
            out = (DATA / "trufflehog.jsonl").read_bytes()
        elif name == "zizmor":
            return subprocess.CompletedProcess(argv, 14, (DATA / "zizmor.json").read_bytes(), b"")
        elif name == "docker":
            out = (DATA / "checkov.json").read_bytes()
        return subprocess.CompletedProcess(argv, 0, out, b"")

    def argv(self, tool):
        return next(c["argv"] for c in self.calls if Path(c["argv"][0]).name == tool)

    def ran(self, tool):
        return any(Path(c["argv"][0]).name == tool for c in self.calls)


def fake_fetch(name, lock, dest, get=None, plat=None):
    path = dest / name / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    return tools.ToolResult(name, "ok", lock.get(name, {}).get("version", "1"), path)


@pytest.fixture
def workspace(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".github" / "workflows").mkdir(parents=True)
    (ws / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
    (ws / "terraform").mkdir()
    (ws / "terraform" / "s3.tf").write_text('resource "aws_s3_bucket" "invoices" {}\n')
    return ws


def run(workspace, tmp_path, *, event_name="pull_request", event=None, runner=None, environ=None,
        docker="/usr/bin/docker", has_scan=True, **options):
    opts = scan.ScanOptions(enabled=options.pop("enabled", True), verify_secrets=options.pop("verify", False),
                            osv_offline=options.pop("offline", False), timeout_s=600)
    runner = runner or FakeRunner()
    result = scan.run_scan(workspace, event_name, PR_EVENT if event is None else event, opts, has_scan=has_scan,
                           out_dir=tmp_path / "agent", artifacts_dir=tmp_path / "artifacts",
                           tools_dir=tmp_path / "tools", runner=runner, fetch=fake_fetch, docker=docker,
                           environ=environ or {"PATH": "/usr/bin", "HOME": "/home/runner"})
    return result, runner


def test_a_full_scan(workspace, tmp_path):
    result, runner = run(workspace, tmp_path)
    doc = result.doc
    assert doc["schema"] == "securacy-scan:v1" and doc["secrets_scope"] == "change"
    assert {t: v["status"] for t, v in doc["tools"].items()} == {
        "syft": "ok", "grype": "ok", "osv-scanner": "ok", "gitleaks": "ok", "zizmor": "ok", "checkov": "ok",
        "trufflehog": "skipped"}
    assert any(c["purl"] == "pkg:npm/lodash@4.17.20" for c in doc["components"])
    assert any(v["id"] == "GHSA-35jh-r3h4-6jhm" and v["tools"] == ["grype", "osv-scanner"]
               for v in doc["vulnerabilities"])
    assert doc["secrets"][0]["rule"] == "stripe-access-token"
    assert {w["rule"] for w in doc["workflows"]} >= {"unpinned-uses", "dangerous-triggers"}
    assert any(i["rule"] == "CKV_AWS_20" for i in doc["iac"]) and doc["iac_resources"]
    assert json.loads((tmp_path / "agent" / "scan.json").read_text()) == doc
    assert result.sbom_path == tmp_path / "artifacts" / "sbom.cdx.json" and result.sbom_path.is_file()


def test_scan_off_writes_nothing(workspace, tmp_path):
    result, runner = run(workspace, tmp_path, enabled=False)
    assert result.doc is None and runner.calls == [] and not (tmp_path / "agent" / "scan.json").exists()


def test_each_tool_failure_is_isolated(workspace, tmp_path):
    result, runner = run(workspace, tmp_path, runner=FakeRunner(fail={"syft", "zizmor"}))
    tools_state = {t: v["status"] for t, v in result.doc["tools"].items()}
    assert tools_state["syft"] == "failed" and tools_state["grype"] == "skipped" and tools_state["zizmor"] == "failed"
    assert tools_state["gitleaks"] == "ok" and tools_state["osv-scanner"] == "ok"
    assert result.doc["secrets"] and not result.doc["workflows"]
    assert not runner.ran("grype")


def test_secret_scan_falls_back_to_tree_when_range_is_missing(workspace, tmp_path):
    result, runner = run(workspace, tmp_path, runner=FakeRunner(git_ok=False))
    assert result.doc["secrets_scope"] == "tree"
    assert runner.argv("gitleaks")[1] == "dir"
    assert any("full sweep of the working tree" in n for n in result.notices)


def test_secret_ranges_per_event(workspace, tmp_path):
    _, runner = run(workspace, tmp_path)
    assert f"--log-opts={BASE}..{HEAD}" in runner.argv("gitleaks")
    push = {"before": BASE, "after": HEAD}
    result, runner = run(workspace, tmp_path, event_name="push", event=push)
    assert result.doc["secrets_scope"] == "push" and f"--log-opts={BASE}..{HEAD}" in runner.argv("gitleaks")
    result, runner = run(workspace, tmp_path, event_name="push", event={"before": "0" * 40, "after": HEAD})
    assert result.doc["secrets_scope"] == "tree"
    result, runner = run(workspace, tmp_path, event_name="workflow_dispatch", event={}, has_scan=False)
    assert result.doc["secrets_scope"] == "history" and runner.argv("gitleaks")[1] == "git"
    assert not any(a.startswith("--log-opts") for a in runner.argv("gitleaks"))


def test_command_flags_pinned(workspace, tmp_path):
    _, runner = run(workspace, tmp_path, verify=True, offline=True)
    assert "--redact" in runner.argv("gitleaks")
    th = runner.argv("trufflehog")
    assert "--json" in th and "--no-verification" not in th and "--since-commit" in th
    osv = runner.argv("osv-scanner")
    assert {"--offline-vulnerabilities", "--download-offline-databases", "--no-resolve"} <= set(osv)
    assert "--offline" in runner.argv("zizmor")
    docker = runner.argv("docker")
    assert docker[:5] == ["/usr/bin/docker", "run", "--rm", "--network", "none"]
    mount = docker[docker.index("-v") + 1]
    assert mount.endswith(":/src:ro")
    assert any("@sha256:" in a for a in docker)
    _, runner = run(workspace, tmp_path)
    assert not runner.ran("trufflehog")  # it only runs to verify, which is opt-in
    assert "--no-resolve" not in runner.argv("osv-scanner")


def test_scanners_read_securacys_settings_not_the_repositorys(workspace, tmp_path):
    """A change can't hide its own findings with scanner settings, ignore comments or .gitignore entries
    in its tree. Each flag was checked against the pinned release: without it, a file or comment the
    change adds took that tool's findings to zero (.gitleaks.toml, gitleaks:allow, .syft.yaml exclude,
    .grype.yaml ignore, osv-scanner.toml at any depth, .gitignore for OSV-Scanner, zizmor.yml,
    zizmor: ignore[...], trufflehog:ignore)."""
    own = tmp_path / "tools" / "settings"
    own.mkdir(parents=True)
    (own / "gitleaks.toml").write_text("[allowlist]\npaths = ['''.*''']\n", encoding="utf-8")  # left by anyone
    _, runner = run(workspace, tmp_path, verify=True)
    gitleaks = runner.argv("gitleaks")
    assert gitleaks[gitleaks.index("--config") + 1] == str(own / "gitleaks.toml")
    assert gitleaks[gitleaks.index("--gitleaks-ignore-path") + 1] == str(own)
    assert "--ignore-gitleaks-allow" in gitleaks
    assert runner.argv("syft")[1:3] == ["-c", str(own / "syft.yaml")]
    assert runner.argv("grype")[1:3] == ["-c", str(own / "grype.yaml")]
    osv = runner.argv("osv-scanner")
    assert osv[osv.index("--config") + 1] == str(own / "osv-scanner.toml") and "--no-ignore" in osv
    assert {"--no-config", "--no-ignores"} <= set(runner.argv("zizmor"))
    assert "--no-ignore-tag" in runner.argv("trufflehog")
    assert (own / "gitleaks.toml").read_text(encoding="utf-8") == "[extend]\nuseDefault = true\n"
    assert workspace not in own.parents


class WatchingRunner(FakeRunner):
    """Records whether the workspace's root .gitleaksignore is in place at the moment each scanner starts."""

    def __init__(self):
        super().__init__()
        self.ignore_present = {}

    def __call__(self, argv, cwd=None, **kwargs):
        self.ignore_present[Path(argv[0]).name] = (Path(cwd) / ".gitleaksignore").exists()
        return super().__call__(argv, cwd=cwd, **kwargs)


def test_gitleaks_never_sees_the_repositorys_gitleaksignore(workspace, tmp_path):
    """Gitleaks reads a root .gitleaksignore whatever --gitleaks-ignore-path says (8.30.1), and a fingerprint in
    it hides a finding even in git mode. The file is moved out of the checkout while Gitleaks runs, then put back."""
    entry = "src/payments.js:stripe-access-token:3\n"
    (workspace / ".gitleaksignore").write_text(entry, encoding="utf-8")
    _, runner = run(workspace, tmp_path, runner=WatchingRunner())
    assert runner.ignore_present["gitleaks"] is False
    assert runner.ignore_present["syft"] is True  # only the secret scan needs it out of the way
    assert (workspace / ".gitleaksignore").read_text(encoding="utf-8") == entry


def test_a_leftover_parked_file_does_not_let_the_repositorys_gitleaksignore_stay(workspace, tmp_path):
    """Fail closed: a copy parked by an earlier run on a reused runner must not make the move a no-op, or the
    repository's own .gitleaksignore would stay in place and hide findings."""
    stale = tmp_path / "tools" / "settings" / "aside"
    stale.mkdir(parents=True)
    (stale / ".gitleaksignore").write_text("old\n", encoding="utf-8")
    (workspace / ".gitleaksignore").write_text("src/payments.js:stripe-access-token:3\n", encoding="utf-8")
    _, runner = run(workspace, tmp_path, runner=WatchingRunner())
    assert runner.ignore_present["gitleaks"] is False
    assert (workspace / ".gitleaksignore").read_text(encoding="utf-8") == "src/payments.js:stripe-access-token:3\n"


def test_gitleaks_does_not_run_when_the_gitleaksignore_cannot_be_moved_out(workspace, tmp_path, monkeypatch):
    (workspace / ".gitleaksignore").write_text("x:y:1\n", encoding="utf-8")
    real_move = scan.shutil.move

    def refuse(src, dst, *args, **kwargs):
        if Path(src).name == ".gitleaksignore" and Path(src).parent == workspace:
            raise PermissionError("read-only")
        return real_move(src, dst, *args, **kwargs)

    monkeypatch.setattr(scan.shutil, "move", refuse)
    result, runner = run(workspace, tmp_path)
    assert not runner.ran("gitleaks") and result.doc["tools"]["gitleaks"]["status"] == "failed"
    assert result.doc["secrets"] == [] and any(".gitleaksignore" in n for n in result.notices)
    assert (workspace / ".gitleaksignore").read_text(encoding="utf-8") == "x:y:1\n"


def test_a_gitleaksignore_that_cannot_be_put_back_is_reported(workspace, tmp_path, monkeypatch):
    (workspace / ".gitleaksignore").write_text("x:y:1\n", encoding="utf-8")
    real_move = scan.shutil.move

    def fail_to_restore(src, dst, *args, **kwargs):
        if Path(dst) == workspace / ".gitleaksignore":
            raise OSError("disk full")
        return real_move(src, dst, *args, **kwargs)

    monkeypatch.setattr(scan.shutil, "move", fail_to_restore)
    result, _ = run(workspace, tmp_path)
    assert result.doc["tools"]["gitleaks"]["status"] == "ok"
    assert any("put back" in n and ".gitleaksignore" in n for n in result.notices)


def test_gitleaksignore_comes_back_when_gitleaks_fails(workspace, tmp_path):
    (workspace / ".gitleaksignore").write_text("x:y:1\n", encoding="utf-8")
    _, runner = run(workspace, tmp_path, runner=FakeRunner(fail={"gitleaks"}))
    assert (workspace / ".gitleaksignore").read_text(encoding="utf-8") == "x:y:1\n"
    assert not list(workspace.glob("*aside*"))


def test_no_docker_skips_checkov(workspace, tmp_path):
    result, runner = run(workspace, tmp_path, docker=None)
    assert result.doc["tools"]["checkov"]["status"] == "skipped" and not runner.ran("docker")
    assert any("Docker" in n for n in result.notices)


def test_notices_say_what_was_not_scanned_without_naming_the_scanner(workspace, tmp_path):
    result, _ = run(workspace, tmp_path, runner=FakeRunner(fail={"grype", "gitleaks", "zizmor"}), docker=None)
    assert len(result.notices) >= 4
    for notice in result.notices:
        for name in ("syft", "grype", "osv", "gitleaks", "trufflehog", "zizmor", "checkov"):
            assert name not in notice.lower().replace(".gitleaksignore", ""), notice
    assert set(scan.CHECK_LABELS) == set(scan.TOOL_NAMES)


def test_no_iac_files_skips_checkov_and_no_workflows_skips_zizmor(tmp_path):
    ws = tmp_path / "plain"
    ws.mkdir()
    result, runner = run(ws, tmp_path)
    assert result.doc["tools"]["checkov"]["status"] == "skipped"
    assert result.doc["tools"]["zizmor"]["status"] == "skipped"


def test_no_secret_value_in_any_output(workspace, tmp_path, capsys):
    result, _ = run(workspace, tmp_path, verify=True)
    everything = json.dumps(result.doc) + json.dumps(result.notices) + (tmp_path / "agent" / "scan.json").read_text()
    everything += capsys.readouterr().out
    assert FAKE_SECRET not in everything and "fixture@" not in everything
    payload = ci.build_payload("pull_request", PR_EVENT["pull_request"] and {"pull_request": {"number": 7}},
                               {"GITHUB_REPOSITORY": "acme/app", "GITHUB_SHA": HEAD}, mode="diff", changed=[],
                               agent_report=None, override=None, scan=result.doc)
    assert FAKE_SECRET not in json.dumps(payload) and payload["scan"] == result.doc


def test_subprocess_env_has_no_keys(workspace, tmp_path):
    environ = {"PATH": "/usr/bin", "HOME": "/home/runner", "INPUT_API_KEY": "sk-ci-x", "GITHUB_TOKEN": "ghs_x",
               "ANTHROPIC_API_KEY": "sk-ant-x", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "x"}
    _, runner = run(workspace, tmp_path, environ=environ)
    for call in runner.calls:
        assert not ({"INPUT_API_KEY", "GITHUB_TOKEN", "ANTHROPIC_API_KEY", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"}
                    & set(call["env"])), call["argv"][0]


def test_payload_without_scan_keeps_the_old_contract():
    payload = ci.build_payload("push", {}, {"GITHUB_REPOSITORY": "acme/app", "GITHUB_SHA": HEAD}, mode="sweep",
                               changed=None, agent_report=None, override=None)
    assert "scan" not in payload


def test_scan_command_never_fails_the_job(monkeypatch, tmp_path):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))

    def boom(*a, **k):
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(scan, "run_scan", boom)
    assert ci.main(["scan"]) == 0


def test_check_reads_the_scan_file(monkeypatch, tmp_path):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    (tmp_path / ci.AGENT_DIR).mkdir()
    (tmp_path / ci.AGENT_DIR / "scan.json").write_text(json.dumps({"schema": "securacy-scan:v1"}))
    assert ci.scan_report() == {"schema": "securacy-scan:v1"}
    (tmp_path / ci.AGENT_DIR / "scan.json").write_text("x" * (scan.MAX_SCAN_BYTES + 10))
    assert ci.scan_report() is None


def test_action_yml_scan_step_gets_no_secret_inputs():
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    step = text.split("- id: scan", 1)[1].split("\n    - ", 1)[0]
    assert "securacy_ci.py\" scan" in step
    for forbidden in ("api-key", "agent-api-key", "claude-oauth-token", "github-token", "INPUT_API_KEY"):
        assert forbidden not in step, forbidden
    assert text.index("- id: scan") < text.index("- id: claude")  # before the agent


def test_securacy_ci_finds_its_scan_module_when_loaded_by_path(tmp_path, monkeypatch):
    """Callers (the backend's contract test, other runners) load securacy_ci.py
    by path, without its folder on sys.path."""
    import importlib.util
    monkeypatch.setattr(sys, "path", [p for p in sys.path if Path(p).resolve() != ROOT])
    for name in ("securacy_scan", "securacy_tools"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    spec = importlib.util.spec_from_file_location("securacy_ci_by_path", ROOT / "securacy_ci.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    assert module.scan_report() is None
