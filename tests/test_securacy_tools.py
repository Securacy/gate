"""Tests for securacy_tools.py: pinned scanner downloads. No network: the
download is faked and the archives are built here."""

import hashlib
import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import securacy_tools as tools  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def targz(files, links=()):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for name, target in links:
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
    return buf.getvalue()


def zipped(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def lock_for(data, member="syft", url="https://github.com/anchore/syft/releases/download/v1.0.0/syft.tar.gz"):
    asset = {"url": url, "sha256": hashlib.sha256(data).hexdigest(), "member": member}
    return {"syft": {"version": "1.0.0", "assets": {"linux-x64": asset, "linux-arm64": asset}}}


def test_lock_file_shape():
    lock = tools.load_lock()
    binaries = {"syft", "grype", "osv-scanner", "gitleaks", "trufflehog", "zizmor"}
    assert binaries <= set(lock)
    for name in binaries:
        entry = lock[name]
        assert entry["version"]
        for plat in ("linux-x64", "linux-arm64"):
            asset = entry["assets"][plat]
            assert asset["url"].startswith("https://github.com/") and f"/{entry['version']}" in asset["url"].replace(
                "/v", "/")
            assert len(asset["sha256"]) == 64 and int(asset["sha256"], 16) >= 0
            assert asset["member"] is None or "/" not in asset["member"]
    assert "@sha256:" in lock["checkov"]["image"] and len(lock["checkov"]["image"].split("@sha256:")[1]) == 64


def test_fetch_tool_extracts_the_named_member(tmp_path):
    data = targz({"syft": b"#!/bin/sh\necho syft\n", "README.md": b"x"})
    result = tools.fetch_tool("syft", lock_for(data), tmp_path, get=lambda url: data, plat="linux-x64")
    assert result.status == "ok" and result.version == "1.0.0"
    assert result.path.read_bytes() == b"#!/bin/sh\necho syft\n"
    assert not (tmp_path / "README.md").exists()


def test_a_raw_binary_asset_is_written_as_is(tmp_path):
    data = b"\x7fELF fake osv-scanner"
    lock = lock_for(data, member=None)
    result = tools.fetch_tool("syft", lock, tmp_path, get=lambda url: data, plat="linux-arm64")
    assert result.status == "ok" and result.path.read_bytes() == data


def test_checksum_mismatch_is_unverified_and_nothing_extracted(tmp_path):
    data = targz({"syft": b"real"})
    tampered = targz({"syft": b"evil"})
    result = tools.fetch_tool("syft", lock_for(data), tmp_path, get=lambda url: tampered, plat="linux-x64")
    assert result.status == "unverified" and result.path is None
    assert list(tmp_path.iterdir()) == []


def test_extract_only_named_member(tmp_path):
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(targz({"syft": b"1", "other": b"2"}))
    out = tools.extract_member(archive, "syft", tmp_path / "out")
    assert out.name == "syft" and sorted(p.name for p in (tmp_path / "out").iterdir()) == ["syft"]


@pytest.mark.parametrize("files,links", [
    ({"../syft": b"x"}, ()),
    ({"/syft": b"x"}, ()),
    ({}, (("syft", "/etc/passwd"),)),
    ({"dir/syft": b"x"}, ()),
])
def test_extract_refuses_traversal_symlink_absolute_and_nesting(tmp_path, files, links):
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(targz(files, links))
    with pytest.raises(tools.ToolError):
        tools.extract_member(archive, "syft", tmp_path / "out")


def test_extract_from_zip(tmp_path):
    archive = tmp_path / "a.zip"
    archive.write_bytes(zipped({"gitleaks": b"bin", "LICENSE": b"mit"}))
    assert tools.extract_member(archive, "gitleaks", tmp_path / "out").read_bytes() == b"bin"
    bad = tmp_path / "b.zip"
    bad.write_bytes(zipped({"../gitleaks": b"bin"}))
    with pytest.raises(tools.ToolError):
        tools.extract_member(bad, "gitleaks", tmp_path / "out2")


def test_extract_refuses_oversized_member(tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "MAX_TOOL_BYTES", 3)
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(targz({"syft": b"12345"}))
    with pytest.raises(tools.ToolError):
        tools.extract_member(archive, "syft", tmp_path / "out")


@pytest.mark.parametrize("url", ["http://github.com/x", "https://evil.example/x", "https://github.com.evil.example/x",
                                 "ftp://github.com/x"])
def test_fetch_refuses_http_and_unknown_hosts(url):
    with pytest.raises(tools.ToolError):
        tools.http_get(url)


def test_a_download_failure_is_failed_not_an_exception(tmp_path):
    def broken(url):
        raise tools.ToolError("down")

    result = tools.fetch_tool("syft", lock_for(b"x"), tmp_path, get=broken, plat="linux-x64")
    assert result.status == "failed" and result.path is None


def test_unsupported_platform_skips(tmp_path):
    assert tools.platform_key("Darwin", "arm64") is None
    assert tools.platform_key("Windows", "AMD64") is None
    assert tools.platform_key("Linux", "x86_64") == "linux-x64"
    assert tools.platform_key("Linux", "aarch64") == "linux-arm64"
    result = tools.fetch_tool("syft", lock_for(b"x"), tmp_path, get=lambda url: b"x", plat=None)
    assert result.status == "skipped"


def test_clean_env_drops_every_secret_shaped_variable():
    env = tools.clean_env({
        "PATH": "/usr/bin", "HOME": "/home/runner", "RUNNER_TEMP": "/tmp/r", "LANG": "C.UTF-8",
        "INPUT_API_KEY": "sk-ci-x", "GITHUB_TOKEN": "ghs_x", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "x",
        "ANTHROPIC_API_KEY": "x", "MY_SECRET": "x", "AWS_SESSION_TOKEN": "x", "SOMETHING_ELSE": "y",
    })
    assert env == {"PATH": "/usr/bin", "HOME": "/home/runner", "RUNNER_TEMP": "/tmp/r", "LANG": "C.UTF-8"}


def test_lock_json_is_valid_json_on_disk():
    json.loads((ROOT / "scanners.lock.json").read_text(encoding="utf-8"))
