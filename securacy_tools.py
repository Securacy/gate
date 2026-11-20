"""Pinned scanner binaries for the supply-chain scan.

Every tool comes from scanners.lock.json: a fixed release URL and the SHA-256
from that release's checksums file. The download goes only to GitHub's release
hosts over https, is capped in size, and is checked before anything is
unpacked. From an archive only the one named file is taken out, never a link
or a path outside the tool directory. A tool that fails any of this is not
run, and the scan says so.

Scanners never see this run's secrets: clean_env() is the whole environment
they get. Standard library only, and Python 3.8 compatible.
"""

import hashlib
import io
import json
import os
import platform
import stat
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, Optional

LOCK_PATH = Path(__file__).resolve().parent / "scanners.lock.json"
ALLOWED_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
MAX_TOOL_BYTES = 200 * 1024 * 1024
MAX_REDIRECTS = 5
TIMEOUT_SECONDS = 120
USER_AGENT = "securacy-gate-tools/1"
# What a scanner may see of the runner's environment. Nothing else, so no key,
# token or secret of this job can reach it.
ENV_KEEP = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "RUNNER_TEMP")


class ToolError(Exception):
    """A tool that can't be used: wrong host, too big, unsafe archive, failed download."""


class ToolResult:
    def __init__(self, name: str, status: str, version: str = "", path: Optional[Path] = None) -> None:
        self.name, self.status, self.version, self.path = name, status, version, path

    def __repr__(self) -> str:
        return f"ToolResult({self.name!r}, {self.status!r}, {self.version!r}, {self.path!r})"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # http_get checks every hop itself


_OPENER = urllib.request.build_opener(_NoRedirect)


def load_lock(path: Path = LOCK_PATH) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def platform_key(system: Optional[str] = None, machine: Optional[str] = None) -> Optional[str]:
    """linux-x64 or linux-arm64; None where the scanners aren't offered."""
    system = system if system is not None else platform.system()
    machine = (machine if machine is not None else platform.machine()).lower()
    if system != "Linux":
        return None
    if machine in ("x86_64", "amd64"):
        return "linux-x64"
    if machine in ("aarch64", "arm64"):
        return "linux-arm64"
    return None


def clean_env(environ: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    source = os.environ if environ is None else environ
    return {k: source[k] for k in ENV_KEEP if k in source}


def _check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS or parts.username or parts.password:
        raise ToolError("scanner downloads must be https from GitHub releases")


def http_get(url: str) -> bytes:
    for _ in range(MAX_REDIRECTS + 1):
        _check_url(url)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            # _check_url allowed only https on GitHub's release hosts.
            with _OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:  # nosec B310
                body = response.read(MAX_TOOL_BYTES + 1)
        except urllib.error.HTTPError as error:
            if error.code in (301, 302, 303, 307, 308) and error.headers.get("Location"):
                url = urllib.parse.urljoin(url, error.headers["Location"])
                continue
            raise ToolError(f"download failed with HTTP {error.code}")
        except (urllib.error.URLError, OSError) as error:
            raise ToolError(f"download failed: {type(error).__name__}")
        if len(body) > MAX_TOOL_BYTES:
            raise ToolError("download is too large")
        return body
    raise ToolError("too many redirects")


def sha256_ok(data: bytes, expected: str) -> bool:
    return hashlib.sha256(data).hexdigest() == expected.lower()


def _member_name_ok(name: str, member: str) -> bool:
    return name in (member, "./" + member)


def _write(dest: Path, member: str, data: bytes) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / member
    out.write_bytes(data)
    out.chmod(out.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return out


def extract_member(archive: Path, member: str, dest: Path) -> Path:
    """Take the one file `member` (at the archive's top level) out of a .tar.gz or .zip."""
    if not member or "/" in member or "\\" in member or member in (".", ".."):
        raise ToolError("bad member name")
    raw = archive.read_bytes()
    if zipfile.is_zipfile(io.BytesIO(raw)):
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            infos = [i for i in z.infolist() if _member_name_ok(i.filename, member)]
            if len(infos) != 1:
                raise ToolError(f"{member} not found in the archive")
            info = infos[0]
            if stat.S_ISLNK(info.external_attr >> 16) or info.is_dir():
                raise ToolError(f"{member} is not a regular file")
            if info.file_size > MAX_TOOL_BYTES:
                raise ToolError(f"{member} is too large")
            return _write(dest, member, z.read(info))
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
            infos = [i for i in tar.getmembers() if _member_name_ok(i.name, member)]
            if len(infos) != 1:
                raise ToolError(f"{member} not found in the archive")
            info = infos[0]
            if not info.isreg():
                raise ToolError(f"{member} is not a regular file")
            if info.size > MAX_TOOL_BYTES:
                raise ToolError(f"{member} is too large")
            handle = tar.extractfile(info)
            if handle is None:
                raise ToolError(f"{member} can't be read")
            return _write(dest, member, handle.read(MAX_TOOL_BYTES + 1))
    except tarfile.TarError as error:
        raise ToolError(f"bad archive: {type(error).__name__}")


def fetch_tool(name: str, lock: Dict[str, Any], dest: Path, *, get: Callable[[str], bytes] = http_get,
               plat: Optional[str] = "auto") -> ToolResult:
    """Download, verify and unpack one tool into dest/<name>/. Never raises."""
    entry = lock.get(name) or {}
    version = str(entry.get("version") or "")
    plat = platform_key() if plat == "auto" else plat
    asset = (entry.get("assets") or {}).get(plat) if plat else None
    if not asset:
        return ToolResult(name, "skipped", version)
    try:
        data = get(asset["url"])
        if not sha256_ok(data, asset["sha256"]):
            return ToolResult(name, "unverified", version)
        member = asset.get("member")
        tool_dir = dest / name
        if member is None:
            return ToolResult(name, "ok", version, _write(tool_dir, name, data))
        tool_dir.mkdir(parents=True, exist_ok=True)
        archive = tool_dir / "download"
        archive.write_bytes(data)
        try:
            path = extract_member(archive, member, tool_dir)
        finally:
            archive.unlink()
        return ToolResult(name, "ok", version, path)
    except (ToolError, OSError, KeyError):
        return ToolResult(name, "failed", version)
