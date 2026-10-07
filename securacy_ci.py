#!/usr/bin/env python3
"""SecuracyAI Gate for GitHub Actions.

The project's threat model is fixed and lives in Securacy. This action has
the repository's own coding agent check the code against its rules, then
sends Securacy the agent's report and posts the verdict. Three commands, one
per step of action.yml:

  prepare   fetch the current guardrail file (rules plus their state), pick
            the mode (a full sweep, or a check of this change), and write the
            agent's prompt. The agent runs next, read-only: a built-in one
            (Claude Code, OpenAI Codex) inside action.yml, or the workflow's
            own step, which reads prompt-file and writes report-file.
  check     read the agent's report, keep only evidence that points at real
            files (and, for regressions, at files this change touched), send
            it to Securacy, then post the result: one PR comment kept up to
            date, the job summary, SARIF and report files, and the exit code
            (1 only when the check blocks).
  sync      (the guardrails job, on the default branch) open or refresh a
            pull request that updates .securacy/guardrails/ when Securacy's
            files differ from the committed ones.

Standard library only, so it runs on any runner with Python 3.8+.

Security notes:
  * The key goes only to the configured Securacy URL: HTTPS (plain HTTP is
    allowed for localhost only) and redirects are refused, because urllib
    would otherwise replay the X-API-Key header to whatever host a redirect
    names.
  * The agent never sees the Securacy key, and its report is untrusted: only
    IDs, statuses and file locations that exist in the workspace are sent.
  * Every file read stays inside the workspace; symlinks out of it are refused.
  * An override only counts when the securacy-override label was added by a
    user with admin or maintain permission who also left a written reason.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

COMMENT_MARKER = "<!-- securacy-ci -->"
OVERRIDE_LABEL = "securacy-override"
OVERRIDE_COMMAND = "/securacy-override"
REPORT_SCHEMA = "securacy-report:v2"
MAX_REPORT_BYTES = 2_000_000
MAX_EVIDENCE_FILE_BYTES = 5_000_000
MAX_CHANGED_FILES = 5000
USER_AGENT = "securacy-gate/2"
GUARDRAILS_DIR = ".securacy/guardrails/"
GUARDRAILS_BRANCH = "securacy/guardrails"
AGENT_DIR = "securacy-agent"          # under RUNNER_TEMP
ZERO_SHA = "0" * 40
NEEDS_EVIDENCE = {"IMPLEMENTED", "FIXED", "REGRESSED"}
MAX_DESIGN_CHANGES_SENT = 200  # Securacy keeps 50 after merging duplicates
PROMPTS = Path(__file__).resolve().parent / "prompts"
PROMPT_NAME = "prompt.md"
REPORT_NAME = "report.json"   # where Codex, or a workflow's own agent, writes its reply
# The agents the action runs itself, and the secret each one's model key lives in.
AGENT_SECRETS = {"claude": "ANTHROPIC_API_KEY", "codex": "OPENAI_API_KEY"}
# Read-only tools for Claude: it reads the code and the change, nothing else.
AGENT_TOOLS = "Read,Glob,Grep,Bash(git diff:*),Bash(git log:*),Bash(git show:*)"
AGENT_DENIED = "Edit,Write,MultiEdit,NotebookEdit,WebFetch,WebSearch,Task"

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
# The same path and line rules Securacy applies (report_check.py).
_PATH = re.compile(r"^(?!/)(?!.*//)(?!.*(?:^|/)\.{1,2}(?:/|$))[A-Za-z0-9_.@+/-]{1,300}$")
_LINES = re.compile(r"^\d{1,7}(?:-\d{1,7})?$")
_SHA = re.compile(r"^[0-9a-f]{7,64}$")


class SetupError(Exception):
    """The workflow is misconfigured; the check fails with this message."""


# ---------------------------------------------------------------------------
# GitHub plumbing: inputs, outputs, log commands
# ---------------------------------------------------------------------------

def _input(name: str, default: str = "") -> str:
    return os.environ.get("INPUT_" + name.upper().replace("-", "_"), default).strip()


def _escape_command(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def log(level: str, message: str) -> None:
    """level: notice | warning | error (shown as annotations)."""
    print(f"::{level}::{_escape_command(message)}", flush=True)


def set_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        if "\n" in value:
            delimiter = f"securacy_{os.urandom(8).hex()}"
            fh.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
        else:
            fh.write(f"{name}={value}\n")


def write_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path and markdown:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(markdown.rstrip() + "\n")


# ---------------------------------------------------------------------------
# HTTP without redirects
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise urllib.error.HTTPError(req.full_url, code, f"refused redirect to {newurl}", headers, fp)


_OPENER = urllib.request.build_opener(_NoRedirect)


class HttpResult:
    def __init__(self, status: int, body: Any):
        self.status = status
        self.body = body


def http(method: str, url: str, headers: Dict[str, str], payload: Any = None, timeout: int = 60) -> HttpResult:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Accept": "application/json", "User-Agent": USER_AGENT,
        **({"Content-Type": "application/json"} if data is not None else {}), **headers})
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            raw = exc.read() if exc.fp else b""
        except OSError:  # the server may close the connection after a refused redirect
            raw = b""
    try:
        body = json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        body = None
    return HttpResult(status, body)


# ---------------------------------------------------------------------------
# Configuration and workspace files
# ---------------------------------------------------------------------------

def server_url(raw: str) -> str:
    parsed = urllib.parse.urlparse(raw.rstrip("/"))
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme not in ("https", "http") or not parsed.hostname or (parsed.scheme == "http" and not local):
        raise SetupError("server-url must be an https:// URL.")
    if parsed.query or parsed.fragment or parsed.username:
        raise SetupError("server-url must be a plain base URL.")
    return raw.rstrip("/")


def inside(workspace: Path, relative: str) -> Path:
    """The real path of `relative` under the workspace, or SetupError."""
    root = workspace.resolve()
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        raise SetupError(f"{relative} is outside the repository.")
    return candidate


def agent_dir() -> Path:
    return Path(os.environ.get("RUNNER_TEMP") or ".") / AGENT_DIR


def _event() -> Tuple[str, Dict[str, Any]]:
    name = os.environ.get("GITHUB_EVENT_NAME", "")
    path = os.environ.get("GITHUB_EVENT_PATH")
    return name, json.loads(Path(path).read_text(encoding="utf-8")) if path else {}


def _private(event: Dict[str, Any]) -> bool:
    return bool((event.get("repository") or {}).get("private", True))


# ---------------------------------------------------------------------------
# The GitHub API
# ---------------------------------------------------------------------------

class GitHub:
    def __init__(self, token: str, repository: str, api_url: str):
        self.token = token
        self.repository = repository
        self.api = api_url.rstrip("/")

    def _call(self, method: str, path: str, payload: Any = None) -> HttpResult:
        try:
            return http(method, f"{self.api}/repos/{self.repository}{path}",
                        {"Authorization": f"Bearer {self.token}", "X-GitHub-Api-Version": "2022-11-28"}, payload)
        except (urllib.error.URLError, OSError):
            return HttpResult(0, None)  # treated like any other failed call

    def _pages(self, path: str, limit: int = 30) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for page in range(1, limit + 1):
            result = self._call("GET", f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
            if result.status != 200 or not isinstance(result.body, list):
                break
            items.extend(result.body)
            if len(result.body) < 100:
                break
        return items

    def changed_files(self, pr_number: int) -> List[str]:
        return [f.get("filename", "") for f in self._pages(f"/pulls/{pr_number}/files")]

    def compare_files(self, base: str, head: str) -> Optional[List[str]]:
        result = self._call("GET", f"/compare/{base}...{head}")
        if result.status != 200 or not isinstance(result.body, dict):
            return None
        return [f.get("filename", "") for f in result.body.get("files") or []]

    def override(self, pr_number: int, labels: List[str]) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
        """(override, note). The label alone isn't enough: it must come from
        an admin/maintainer who also commented `/securacy-override <reason>`."""
        if OVERRIDE_LABEL not in labels:
            return None, None
        events = [e for e in self._pages(f"/issues/{pr_number}/events")
                  if e.get("event") == "labeled" and (e.get("label") or {}).get("name") == OVERRIDE_LABEL]
        actor = ((events[-1].get("actor") or {}).get("login") if events else None)
        if not actor:
            return None, "The securacy-override label is set, but who added it couldn't be read."
        permission = self._call("GET", f"/collaborators/{urllib.parse.quote(actor)}/permission")
        level = (permission.body or {}).get("permission") if permission.status == 200 else None
        if level not in ("admin", "maintain"):
            return None, f"Ignored the securacy-override label: @{actor} isn't a repository admin or maintainer."
        reason = None
        for comment in reversed(self._pages(f"/issues/{pr_number}/comments")):
            body = (comment.get("body") or "").strip()
            if (comment.get("user") or {}).get("login") == actor and body.startswith(OVERRIDE_COMMAND + " "):
                reason = body[len(OVERRIDE_COMMAND):].strip().splitlines()[0][:500]
                break
        if not reason:
            return None, f"Override not applied: @{actor}, comment `{OVERRIDE_COMMAND} <reason>` on the PR to give a reason."
        return {"by": actor, "reason": reason}, None

    def upsert_comment(self, pr_number: int, body: str) -> bool:
        for comment in self._pages(f"/issues/{pr_number}/comments"):
            if (comment.get("body") or "").startswith(COMMENT_MARKER) and (comment.get("user") or {}).get("type") == "Bot":
                return self._call("PATCH", f"/issues/comments/{comment['id']}", {"body": body}).status == 200
        return self._call("POST", f"/issues/{pr_number}/comments", {"body": body}).status == 201

    def propose_files(self, base_branch: str, base_sha: str, files: Dict[str, str], *, branch: str,
                      title: str, body: str) -> Optional[str]:
        """Commit `files` on top of base_sha to `branch` (force-moved) and
        open a pull request into base_branch, or reuse the open one. Returns
        the pull request's URL, or None when GitHub refused a step."""
        commit = self._call("GET", f"/git/commits/{base_sha}")
        if commit.status != 200:
            return None
        tree = self._call("POST", "/git/trees", {
            "base_tree": commit.body["tree"]["sha"],
            "tree": [{"path": p, "mode": "100644", "type": "blob", "content": c} for p, c in sorted(files.items())]})
        if tree.status != 201:
            return None
        made = self._call("POST", "/git/commits", {"message": title, "tree": tree.body["sha"], "parents": [base_sha]})
        if made.status != 201:
            return None
        sha = made.body["sha"]
        moved = self._call("PATCH", f"/git/refs/heads/{branch}", {"sha": sha, "force": True})
        if moved.status != 200:
            moved = self._call("POST", "/git/refs", {"ref": f"refs/heads/{branch}", "sha": sha})
            if moved.status != 201:
                return None
        owner = self.repository.split("/")[0]
        existing = self._call("GET", f"/pulls?state=open&head={owner}:{branch}&base={urllib.parse.quote(base_branch)}")
        if existing.status == 200 and existing.body:
            return existing.body[0].get("html_url")
        opened = self._call("POST", "/pulls", {"title": title, "head": branch, "base": base_branch, "body": body})
        return opened.body.get("html_url") if opened.status == 201 and isinstance(opened.body, dict) else None


def _github() -> Optional[GitHub]:
    token = _input("github-token")
    if not token:
        return None
    return GitHub(token, os.environ["GITHUB_REPOSITORY"], os.environ.get("GITHUB_API_URL", "https://api.github.com"))


# ---------------------------------------------------------------------------
# Securacy
# ---------------------------------------------------------------------------

def _detail(result: HttpResult) -> str:
    body = result.body if isinstance(result.body, dict) else {}
    detail = body.get("detail")
    if isinstance(detail, dict):
        errors = "; ".join(f"{e.get('field')}: {e.get('message')}" for e in detail.get("errors") or [])
        return f"{detail.get('message', 'Invalid request.')} {errors}".strip()
    return str(detail or body.get("error") or f"HTTP {result.status}")


def submit(url: str, key: str, payload: Dict[str, Any], attempts: int = 3) -> Dict[str, Any]:
    """POST /cicd/analyze. Retries network errors and 5xx (the server
    de-duplicates by commit and input). Returns the run, or an error dict
    with `outcome` set like the server would."""
    for attempt in range(1, attempts + 1):
        try:
            result = http("POST", f"{url}/cicd/analyze", {"X-API-Key": key}, payload)
        except (urllib.error.URLError, OSError) as exc:
            result = HttpResult(0, {"detail": str(getattr(exc, "reason", exc))})
        if result.status in (200, 202) and isinstance(result.body, dict):
            return result.body
        if 300 <= result.status < 400:
            return {"status": "error", "outcome": "block",
                    "message": "server-url redirects somewhere else; set it to the final https:// URL."}
        if result.status in (401, 403, 413, 422):
            return {"status": "error", "outcome": "block", "message": _detail(result)}
        if result.status == 429 or attempt == attempts:
            return {"status": "error", "outcome": "warn",
                    "message": f"Securacy is unavailable right now ({_detail(result)}). Not checked."}
        time.sleep(2 ** attempt)
    return {"status": "error", "outcome": "warn", "message": "Securacy is unavailable right now. Not checked."}


def wait_for(url: str, key: str, run: Dict[str, Any], timeout_seconds: int) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    run_url = f"{url}/cicd/runs/{urllib.parse.quote(str(run['run_id']))}"
    while run.get("status") in ("queued", "running"):
        if time.monotonic() > deadline:
            return {"status": "error", "outcome": "warn",
                    "message": "The check is taking longer than the action waits. Not checked; re-run later."}
        time.sleep(min(max(int(run.get("poll_after_seconds") or 10), 5), 30))
        try:
            result = http("GET", run_url, {"X-API-Key": key})
        except (urllib.error.URLError, OSError):
            continue
        if result.status == 200 and isinstance(result.body, dict):
            run = result.body
        elif result.status not in (429, 500, 502, 503, 504):
            return {"status": "error", "outcome": "warn", "message": f"Couldn't read the result ({_detail(result)})."}
    return run


def fetch_guardrails(url: str, key: str) -> Optional[Dict[str, Any]]:
    """GET /cicd/guardrails: the current files and whether a state exists."""
    try:
        result = http("GET", f"{url}/cicd/guardrails", {"X-API-Key": key})
    except (urllib.error.URLError, OSError):
        return None
    if result.status == 200 and isinstance(result.body, dict):
        return result.body
    if result.status in (401, 403):
        raise SetupError(f"Securacy refused the key: {_detail(result)}")
    return None


# ---------------------------------------------------------------------------
# prepare: mode, changed files and the agent's prompt
# ---------------------------------------------------------------------------

def choose_mode(requested: str, event_name: str, has_state: bool, base: Optional[str]) -> str:
    """A full sweep when asked or by hand, when nothing has been
    checked yet, or when there's no earlier commit to compare with."""
    if requested in ("sweep", "diff"):
        return requested if requested == "sweep" or base else "sweep"
    if event_name == "workflow_dispatch" or not has_state or not base:
        return "sweep"
    return "diff"


def base_commit(event_name: str, event: Dict[str, Any]) -> Optional[str]:
    if event_name == "pull_request":
        sha = ((event.get("pull_request") or {}).get("base") or {}).get("sha")
    elif event_name == "push":
        sha = event.get("before")
    else:
        sha = None
    sha = str(sha or "").lower()
    return sha if _SHA.fullmatch(sha) and sha != ZERO_SHA else None


def _git_changed_files(workspace: Path, base: str) -> Optional[List[str]]:
    try:
        out = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"], cwd=workspace, capture_output=True,
                             text=True, timeout=120, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return [line.strip() for line in out.splitlines() if line.strip()]


def changed_files(workspace: Path, event_name: str, event: Dict[str, Any], base: str,
                  github: Optional[GitHub]) -> Optional[List[str]]:
    """The files this change touched: from git (the checkout has the history),
    else from GitHub's API. Only paths Securacy accepts are kept."""
    files = _git_changed_files(workspace, base)
    if files is None and github:
        pr = (event.get("pull_request") or {}).get("number")
        files = github.changed_files(pr) if event_name == "pull_request" and pr else \
            github.compare_files(base, os.environ.get("GITHUB_SHA", "HEAD"))
    if files is None:
        return None
    return sorted({f for f in files if _PATH.fullmatch(f)})[:MAX_CHANGED_FILES]


def build_prompt(mode: str, *, guardrails_file: str, baseline_version: Any, base: Optional[str],
                 changed_files_file: str, report_example: str) -> str:
    text = (PROMPTS / f"{mode}.md").read_text(encoding="utf-8")
    values = {"GUARDRAILS_FILE": guardrails_file, "BASELINE_VERSION": str(baseline_version),
              "BASE": base or "", "CHANGED_FILES_FILE": changed_files_file, "REPORT_EXAMPLE": report_example}
    for name, value in values.items():
        text = text.replace("{{" + name + "}}", value)
    return text


def report_example(mode: str, baseline_version: Any) -> str:
    """The report's shape with empty lists, for the prompt."""
    return json.dumps({"schema": REPORT_SCHEMA, "mode": mode, "baseline_version": baseline_version,
                       "rules": [], "component_map": {}, "design_changes": []})


def claude_args(directory: Path) -> str:
    args = [f'--allowedTools "{AGENT_TOOLS}"', f'--disallowedTools "{AGENT_DENIED}"',
            f"--add-dir {directory.as_posix()}"]
    turns = _input("agent-max-turns", "100")
    if turns.isdigit():
        args.append(f"--max-turns {turns}")
    model = _input("agent-model")
    if model and re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", model):
        args.append(f"--model {model}")
    return " ".join(args)


def prepare() -> int:
    set_output("run-agent", "false")
    key = _input("api-key")
    if not key:
        return 0  # check says why
    print(f"::add-mask::{key}", flush=True)
    url = server_url(_input("server-url"))
    workspace = Path(os.environ.get("GITHUB_WORKSPACE") or ".")
    event_name, event = _event()
    directory = agent_dir()
    directory.mkdir(parents=True, exist_ok=True)

    current = fetch_guardrails(url, key)
    files = (current or {}).get("files") or []
    flavor = (current or {}).get("agent_flavor") or "claude"
    agent_file = next((f for f in files if f.get("flavor") == flavor), None)
    base = base_commit(event_name, event)
    mode = choose_mode(_input("mode", "auto"), event_name, bool((current or {}).get("has_state")), base)
    context: Dict[str, Any] = {"mode": mode, "base": base, "changed_files": None,
                               "baseline_version": (current or {}).get("baseline_version")}

    if mode == "diff":
        changed = changed_files(workspace, event_name, event, base, _github())
        if changed is None:
            log("warning", "Couldn't list the files this change touched, so this run does a full sweep.")
            mode = context["mode"] = "sweep"
        else:
            context["changed_files"] = changed
    set_output("mode", mode)

    if agent_file and _SAFE_NAME.match(str(agent_file.get("filename") or "")):
        guardrails_path = directory / agent_file["filename"]
        guardrails_path.write_text(str(agent_file.get("content") or ""), encoding="utf-8")
        context["guardrails_sha256"] = agent_file.get("sha256")
    else:
        guardrails_path = None
        log("warning" if current else "notice",
            "Securacy has no guardrails for this repository yet (pick its threat model in Securacy)."
            if current else "Couldn't fetch the guardrails from Securacy.")

    if mode == "diff" and not context["changed_files"]:
        context["empty_change"] = True  # nothing to read: an empty report says so
    (directory / "context.json").write_text(json.dumps(context), encoding="utf-8")

    agent = _agent()
    report_path = directory / REPORT_NAME
    report_path.unlink(missing_ok=True)
    set_output("report-file", report_path.as_posix())
    if not guardrails_path or context.get("empty_change"):
        return 0

    changed_path = directory / "changed-files.txt"
    changed_path.write_text("\n".join(context["changed_files"] or []) + "\n", encoding="utf-8")
    example = report_example(mode, context["baseline_version"])
    prompt = build_prompt(mode, guardrails_file=guardrails_path.as_posix(),
                          baseline_version=context["baseline_version"], base=base,
                          changed_files_file=changed_path.as_posix(), report_example=example)
    prompt_path = directory / PROMPT_NAME
    prompt_path.write_text(prompt, encoding="utf-8")
    set_output("prompt-file", prompt_path.as_posix())
    set_output("guardrails-file", guardrails_path.as_posix())

    if _input("report-file"):
        return 0  # the workflow's own step wrote the report somewhere else
    if agent != "custom" and _input("agent-key-set") != "true":
        where = ("the CLAUDE_CODE_OAUTH_TOKEN secret (a Claude Pro or Max subscription's token from "
                 "`claude setup-token`) or the ANTHROPIC_API_KEY secret" if agent == "claude"
                 else f"the {AGENT_SECRETS[agent]} secret")
        log("warning", f"No model key for the coding agent, so it didn't run and the code isn't checked. "
                       f"Add {where}.")
        return 0
    if agent != "custom":
        set_output("prompt", prompt)
    if agent == "claude":
        set_output("claude-args", claude_args(directory))
    set_output("run-agent", "true")
    print(f"Securacy: {'full sweep' if mode == 'sweep' else 'checking this change'} with the coding agent.", flush=True)
    return 0


def _agent() -> str:
    """The agent the action runs itself (claude, codex), or custom when the
    workflow brings its own: the prepare command, or agent: custom."""
    if _input("command", "check") == "prepare":
        return "custom"
    agent = _input("agent", "claude") or "claude"
    if agent not in AGENT_SECRETS and agent != "custom":
        raise SetupError(f"agent must be one of {', '.join(sorted(AGENT_SECRETS))} or custom.")
    return agent


# ---------------------------------------------------------------------------
# check: the agent's report, cleaned and sent
# ---------------------------------------------------------------------------

def _json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """The last ```json block in the agent's reply, else its outermost object."""
    candidates = []
    if "{" in text:
        candidates.append(text[text.index("{"): text.rindex("}") + 1])
    candidates += re.findall(r"```(?:json)?\s*\n(.*?)\n```", text, re.S)
    for raw in reversed(candidates):  # the last fenced block first, the outermost object last
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(value, dict) and value.get("schema") == REPORT_SCHEMA:
            return value
    return None


def report_from_execution(path: str) -> Optional[Dict[str, Any]]:
    """The report from claude-code-action's execution file: the final result
    message, else the last assistant text that holds one."""
    file = Path(path)
    if not path or not file.is_file() or file.stat().st_size > 50_000_000:
        return None
    try:
        messages = json.loads(file.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    texts: List[str] = []
    for message in messages if isinstance(messages, list) else []:
        if not isinstance(message, dict):
            continue
        if message.get("type") == "result" and isinstance(message.get("result"), str):
            texts.append(message["result"])
        content = (message.get("message") or {}).get("content") if message.get("type") == "assistant" else None
        for block in content if isinstance(content, list) else []:
            if isinstance(block, dict) and block.get("type") == "text":
                texts.append(str(block.get("text") or ""))
    for text in reversed(texts):
        report = _json_from_text(text)
        if report:
            return report
    return None


def report_from_reply(path: Path) -> Optional[Dict[str, Any]]:
    """The report in a reply an agent wrote to a file (Codex's output file, or
    a workflow's own agent step): the whole reply, JSON or text around it."""
    if not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
        return None
    try:
        return _json_from_text(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        return None


def report_from_file(workspace: Path, relative: str) -> Optional[Dict[str, Any]]:
    """A report a workflow's own agent wrote (the report-file input)."""
    path = inside(workspace, relative)
    if not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        log("warning", f"{relative} isn't valid JSON.")
        return None
    return value if isinstance(value, dict) else None


def _line_count(path: Path) -> int:
    with open(path, "rb") as fh:
        data = fh.read()
    return data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)


def _touches(evidence: List[Dict[str, str]], changed: Set[str]) -> bool:
    return any(e["path"] in changed or (e["path"].endswith("/") and any(c.startswith(e["path"]) for c in changed))
               for e in evidence)


def clean_evidence(raw: Any, workspace: Path) -> List[Dict[str, str]]:
    """Evidence that points at something real: a file in the workspace (with
    line numbers inside it) or a folder, never anything outside it."""
    out: List[Dict[str, str]] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        path, lines = str(item.get("path") or ""), str(item.get("lines") or "")
        if not _PATH.fullmatch(path) or (lines and not _LINES.fullmatch(lines)):
            continue
        try:
            target = inside(workspace, path)
        except SetupError:
            continue
        if path.endswith("/"):
            if target.is_dir():
                out.append({"path": path})
            continue
        if not target.is_file():
            continue
        if lines:
            start, _, end = lines.partition("-")
            last = int(end or start)
            if int(start) < 1 or last < int(start) or (target.stat().st_size <= MAX_EVIDENCE_FILE_BYTES
                                                         and last > _line_count(target)):
                continue
        out.append({"path": path, "lines": lines} if lines else {"path": path})
    return out


def clean_design_changes(raw: List[Any], workspace: Path, mode: str,
                         changed: Set[str]) -> Tuple[List[Dict[str, Any]], int]:
    """Design changes whose evidence exists, and in a change check only
    evidence in a changed file, since the change must be what adds them.
    Securacy checks the kind and name. Returns them and how many were dropped."""
    out: List[Dict[str, Any]] = []
    dropped = max(len(raw) - MAX_DESIGN_CHANGES_SENT, 0)
    for item in raw[:MAX_DESIGN_CHANGES_SENT]:
        evidence = clean_evidence(item.get("evidence"), workspace) if isinstance(item, dict) else []
        if mode == "diff":
            evidence = [e for e in evidence if _touches([e], changed)]
        if not evidence:
            dropped += 1
            continue
        out.append({"kind": str(item.get("kind") or "")[:40], "name": str(item.get("name") or "")[:100],
                    "evidence": evidence})
    return out, dropped


def clean_report(report: Dict[str, Any], workspace: Path, mode: str,
                 changed: Optional[List[str]]) -> Tuple[Dict[str, Any], int]:
    """The report with evidence checked against the checkout. A claim that a
    control is in place, or that the change removed one, keeps only evidence
    that exists, and a regression or a forbidden pattern only evidence in a
    changed file. Claims left without evidence are dropped. Design changes
    keep only real evidence too, and in a change check only evidence in a
    changed file. Returns the cleaned report and how many claims were dropped."""
    changed_set = set(changed or [])
    dropped = 0
    rules = []
    for rule in report.get("rules") if isinstance(report.get("rules"), list) else []:
        if not isinstance(rule, dict):
            continue
        cleaned: Dict[str, Any] = {"id": rule.get("id"), "controls": []}
        if rule.get("introduced") is True:
            evidence = clean_evidence(rule.get("evidence"), workspace)
            if mode == "diff":
                evidence = [e for e in evidence if _touches([e], changed_set)]
            if evidence:
                cleaned.update(introduced=True, evidence=evidence)
            else:
                dropped += 1
        for control in rule.get("controls") if isinstance(rule.get("controls"), list) else []:
            if not isinstance(control, dict):
                continue
            status = str(control.get("status") or "").strip().upper()
            evidence = clean_evidence(control.get("evidence"), workspace)
            if status == "REGRESSED" and mode == "diff":
                evidence = [e for e in evidence if _touches([e], changed_set)]
            if status in NEEDS_EVIDENCE and not evidence:
                dropped += 1
                continue
            cleaned["controls"].append({"id": control.get("id"), "status": status, "evidence": evidence})
        rules.append(cleaned)
    component_map = report.get("component_map") if isinstance(report.get("component_map"), dict) else {}
    cleaned = {"schema": report.get("schema"), "mode": report.get("mode"),
               "baseline_version": report.get("baseline_version"), "rules": rules,
               "component_map": component_map}
    if isinstance(report.get("design_changes"), list):
        cleaned["design_changes"], design_dropped = clean_design_changes(
            report["design_changes"], workspace, mode, changed_set)
        dropped += design_dropped
        if design_dropped:
            # Securacy must not read the shortened list as complete.
            cleaned["design_changes_dropped"] = design_dropped
    return cleaned, dropped


def build_payload(event_name: str, event: Dict[str, Any], env: Dict[str, str], *, mode: str,
                  changed: Optional[List[str]], agent_report: Optional[Dict[str, Any]],
                  override: Optional[Dict[str, str]]) -> Dict[str, Any]:
    pull = event.get("pull_request") or {}
    head_commit = event.get("head_commit") or {}
    events = ("pull_request", "push", "workflow_dispatch", "schedule")
    payload: Dict[str, Any] = {
        "repository": env["GITHUB_REPOSITORY"],
        "event": event_name if event_name in events else "workflow_dispatch",
        "sha": (pull.get("head") or {}).get("sha") or env["GITHUB_SHA"],
        "ref": env.get("GITHUB_REF"),
        "private": _private(event),
        "mode": mode,
        "changed_files": changed if mode == "diff" else None,
        "agent_report": agent_report,
        "override": override,
    }
    if event_name == "pull_request":
        payload["pr_number"] = pull.get("number") or event.get("number")
    if head_commit.get("timestamp"):
        payload["commit_time"] = head_commit["timestamp"]
    return payload


def write_artifacts(directory: Path, run: Dict[str, Any]) -> Optional[str]:
    """Files for upload-artifact and upload-sarif. Returns the SARIF path."""
    directory.mkdir(parents=True, exist_ok=True)
    sarif_path = None
    if run.get("sarif"):
        sarif_path = directory / "securacy.sarif"
        sarif_path.write_text(json.dumps(run["sarif"], indent=2), encoding="utf-8")
    if run.get("report_markdown"):
        (directory / "securacy-report.md").write_text(run["report_markdown"], encoding="utf-8")
    if run.get("results"):
        (directory / "securacy-results.json").write_text(json.dumps(run["results"], indent=2), encoding="utf-8")
    for item in run.get("guardrails") or []:
        name = str(item.get("filename") or "")
        if _SAFE_NAME.match(name):  # the server names them; never trust a path here
            (directory / "guardrails").mkdir(exist_ok=True)
            (directory / "guardrails" / name).write_text(str(item.get("content") or ""), encoding="utf-8")
    return str(sarif_path) if sarif_path else None


def _minutes(raw: str) -> int:
    try:
        return max(1, min(int(raw), 60))
    except ValueError:
        return 15


def _context() -> Dict[str, Any]:
    path = agent_dir() / "context.json"
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}


def check() -> int:
    env = os.environ
    key = _input("api-key")
    if not key:
        log("notice", "Securacy skipped: no API key is available to this run (PRs from forks and "
                      "Dependabot don't receive secrets).")
        set_output("outcome", "skipped")
        return 0
    print(f"::add-mask::{key}", flush=True)

    url = server_url(_input("server-url"))
    workspace = Path(env.get("GITHUB_WORKSPACE") or ".")
    event_name, event = _event()
    github = _github()
    pr_number = (event.get("pull_request") or {}).get("number") if event_name == "pull_request" else None
    context = _context()
    mode = context.get("mode") or ("diff" if base_commit(event_name, event) else "sweep")
    changed = context.get("changed_files")

    report = None
    if _input("report-file"):
        report = report_from_file(workspace, _input("report-file"))
    elif context.get("empty_change"):
        report = {"schema": REPORT_SCHEMA, "mode": "diff", "baseline_version": context.get("baseline_version"),
                  "rules": [], "component_map": {}}
    else:
        # Wherever the agent left its reply: the reply file (Codex, or a
        # workflow's own agent), Claude's execution file, or Codex's message.
        report = (report_from_reply(agent_dir() / REPORT_NAME)
                  or report_from_execution(_input("agent-output"))
                  or _json_from_text(_input("agent-message")[:MAX_REPORT_BYTES]))
        if report is None and (_input("agent-outcome") not in ("", "skipped") or context.get("guardrails_sha256")):
            log("warning", "The coding agent finished without a usable report, so the code isn't checked.")
    if report is not None:
        report, dropped = clean_report(report, workspace, mode, changed)
        if dropped:
            log("warning", f"{dropped} claims in the agent's report pointed at no real file (or at a file this "
                           "change didn't touch) and were left out.")

    override, override_note = (None, None)
    if pr_number and github:
        labels = [label.get("name") for label in (event.get("pull_request") or {}).get("labels") or []]
        override, override_note = github.override(pr_number, labels)
    if override_note:
        log("warning", override_note)

    payload = build_payload(event_name, event, dict(env), mode=mode, changed=changed, agent_report=report,
                            override=override)
    result = submit(url, key, payload)
    if result.get("status") in ("queued", "running"):
        result = wait_for(url, key, result, _minutes(_input("timeout-minutes", "15")) * 60)

    outcome = result.get("outcome") or "warn"
    summary = result.get("summary_markdown") or f"### SecuracyAI Gate\n\n{result.get('message', '')}"
    write_summary(summary + (f"\n\n{override_note}" if override_note else ""))

    comment = result.get("comment_markdown")
    if pr_number and github and comment and _input("comment", "true").lower() != "false":
        if not github.upsert_comment(pr_number, comment):
            log("warning", "Couldn't post the PR comment (the token needs pull-requests: write).")

    artifacts = Path(env.get("RUNNER_TEMP") or workspace) / "securacy"
    sarif = write_artifacts(artifacts, result)
    set_output("outcome", outcome)
    set_output("artifacts-dir", str(artifacts))
    set_output("sarif-file", sarif or "")
    set_output("run-url", result.get("web_url") or "")

    message = result.get("message") or f"SecuracyAI Gate: {outcome}."
    if outcome == "block":
        log("error", message if result.get("status") == "error" else "Securacy blocked this change. See the PR comment.")
        return 1
    if outcome == "warn":
        log("warning", message if result.get("status") == "error" else "Securacy passed with warnings. See the PR comment.")
    return 0


# ---------------------------------------------------------------------------
# sync: a pull request that updates .securacy/guardrails/
# ---------------------------------------------------------------------------

SYNC_TITLE = "SecuracyAI Gate: update guardrails"
SYNC_BODY = ("Securacy regenerated the guardrail files: the rule statuses changed after the last check on "
             "the default branch. Merge this so everyone's coding agent sees the current state. "
             "The rules themselves are unchanged; don't edit these files by hand.")


def sync() -> int:
    env = os.environ
    key = _input("api-key")
    if not key:
        log("notice", "Securacy guardrails not synced: no API key is available to this run.")
        return 0
    print(f"::add-mask::{key}", flush=True)
    url = server_url(_input("server-url"))
    workspace = Path(env.get("GITHUB_WORKSPACE") or ".")
    _, event = _event()
    if not _private(event):
        log("notice", "Guardrails stay in Securacy for public repositories, so no pull request is opened.")
        return 0
    current = fetch_guardrails(url, key)
    if current is None:
        log("warning", "Couldn't fetch the guardrails from Securacy. Not synced.")
        return 0
    committed = set(current.get("committed_flavors") or [])
    files: Dict[str, str] = {}
    for item in current.get("files") or []:
        name = str(item.get("filename") or "")
        if item.get("flavor") not in committed or not _SAFE_NAME.match(name):
            continue
        target = inside(workspace, GUARDRAILS_DIR + name)
        content = str(item.get("content") or "")
        if not target.is_file() or target.read_text(encoding="utf-8").replace("\r\n", "\n") != content:
            files[GUARDRAILS_DIR + name] = content
    if not files:
        print("Securacy: the guardrail files are up to date.", flush=True)
        set_output("outcome", "unchanged")
        return 0
    github = _github()
    if not github:
        log("warning", "No github-token, so the guardrails pull request couldn't be opened.")
        return 0
    branch = (env.get("GITHUB_REF") or "").replace("refs/heads/", "", 1) or "main"
    pr = github.propose_files(branch, env["GITHUB_SHA"], files, branch=GUARDRAILS_BRANCH, title=SYNC_TITLE,
                              body=SYNC_BODY)
    if not pr:
        log("warning", "GitHub refused the guardrails pull request. The guardrails job needs contents: write and "
                       "pull-requests: write, and 'Allow GitHub Actions to create pull requests' in the "
                       "repository's Actions settings.")
        return 0
    print(f"Securacy: guardrails pull request {pr}", flush=True)
    set_output("outcome", "proposed")
    set_output("pull-request", pr)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Setup mistakes fail the step; anything unexpected only warns, so a
    hiccup on GitHub's or Securacy's side never blocks someone's PR."""
    command = (argv if argv is not None else sys.argv[1:] or ["check"])[0]
    handlers = {"prepare": prepare, "check": check, "sync": sync}
    if command not in handlers:
        log("error", f"Unknown command {command!r}.")
        return 1
    try:
        return handlers[command]()
    except SetupError as exc:
        log("error", str(exc))
        set_output("outcome", "block")
        return 1
    except Exception as exc:  # noqa: BLE001
        log("warning", f"Securacy {command} didn't complete ({type(exc).__name__}). Not checked.")
        set_output("outcome", "warn")
        return 0


if __name__ == "__main__":
    sys.exit(main())
