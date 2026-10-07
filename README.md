<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/securacy-logo-dark.png">
    <img alt="Securacy" src="assets/securacy-logo-light.png" height="48">
  </picture>
</p>

# Securacy Gate

Checks your code against your threat model on every pull request. The threat model is fixed and
lives in Securacy. Its threats become **rules** with **controls** (`T005.C1`, `T005.C2`, …) in a
guardrail file. Your own coding agent reads the code in your CI, with your model key, and reports
which controls are in place. Securacy keeps that as each rule's state, and comments on the pull
request with what the change **fixed** and what it **made worse**.

```
[Securacy logo]

### Threat check: Blocked

This change removes security controls or adds code the threat model forbids.

| Repository    | Threat model | Gate  | Check        | Fixed | Made worse | Rules mitigated |
| acme/payments | v1           | Block | Change check | 1     | 1          | 7 of 20         |

#### Made worse by this change (1)
| Rule | Severity | What changed                                            | Where             |
| T019 | High     | Control removed or weakened: `T019.C1` Set Secure flag | `vote/app.py:22`  |

#### Fixed by this change (1)
| Rule | Control                          | Where                 |
| T005 | `T005.C2` Redis ACLs             | `redis/redis.conf:3`  |
```

## How it works

1. **First run: a full sweep.** The agent reads the whole repository against every control and
   reports `IMPLEMENTED`, `MISSING` or `NOT_APPLICABLE`, with the file and lines. Securacy saves this
   as the starting state. It never blocks.
2. **Every pull request: a change check.** The agent reads only the diff, together with the guardrail
   file, which shows each control's state and where it lives. It reports controls the change
   `FIXED` or `REGRESSED`, and Never patterns it introduced. Only a CRITICAL or HIGH rule made worse
   can block. Controls that were already missing are backlog, not the PR's fault.
3. **Merge: the state moves on.** The push to the default branch runs the same check and saves the
   new state. The workflow's guardrails job then opens a pull request that updates
   `.securacy/guardrails/` with the new statuses. Only the statuses change, never the rules, and
   nobody edits the file by hand.
A full sweep happens only for the first run and when you start one by hand (**Actions → Run workflow**).

The agent runs read-only and never sees the Securacy key. Its report is checked twice before it
counts. Here, every cited file must exist with those lines, and a
regression must point at a file the change touched. In Securacy, every ID must belong to the threat
model. Statuses are always labelled as reported by the agent. A human's triage in Securacy
(*Accepted*, *Mitigated*) wins over the agent.

## Choosing the agent

Pick it in Securacy when you connect the repository (you can change it later in the connection's
settings and re-run the setup command). Securacy itself never needs a model key.

| Agent | How it runs | Model key (repository secret) |
|---|---|---|
| `claude` (default) | [`anthropics/claude-code-action/base-action`](https://github.com/anthropics/claude-code-action/tree/main/base-action) with read-only tools (Read, Glob, Grep, read-only git) | `CLAUDE_CODE_OAUTH_TOKEN` with a Claude Pro or Max subscription (run `claude setup-token`), or `ANTHROPIC_API_KEY` |
| `codex` | [`openai/codex-action`](https://github.com/openai/codex-action) with `safety-strategy: read-only` | `OPENAI_API_KEY` |
| your own | any agent, in a step of your own between `command: prepare` and `command: submit` | whatever your agent needs |

Your own agent (Gemini CLI, Copilot CLI, an in-house one…) needs no built-in support. `prepare`
writes the prompt and the guardrail file and gives you their paths. Your step runs the agent with the
prompt and writes its whole reply to `report-file`, and `submit` checks and sends it:

```yaml
      - id: prepare
        uses: securacy-ai/gate@v1
        with:
          command: prepare
          api-key: ${{ secrets.SECURACY_CI_KEY }}
          server-url: "https://<your Securacy API URL>"
      - name: Coding agent
        if: steps.prepare.outputs.run-agent == 'true'
        env:
          PROMPT_FILE: ${{ steps.prepare.outputs.prompt-file }}
          REPORT_FILE: ${{ steps.prepare.outputs.report-file }}
        run: my-agent --read-only --prompt-file "$PROMPT_FILE" > "$REPORT_FILE"   # your agent here
      - id: securacy
        uses: securacy-ai/gate@v1
        with:
          command: submit
          api-key: ${{ secrets.SECURACY_CI_KEY }}
          server-url: "https://<your Securacy API URL>"
```

With your own agent, keeping it read-only is up to your step. The same checks apply to its reply:
evidence must exist in the checkout, and regressions must point at changed files. Keep
`SECURACY_CI_KEY` out of its environment.

## Set up

1. In Securacy, open **Settings → CI/CD → Connect a repository**. Pick the project and the AppSec
   threat run that is the threat model.
2. Run the command it shows, from any folder. It needs the [GitHub CLI](https://cli.github.com), logged
   in as an admin of the repository:

   ```bash
   curl -fsSL https://<api>/cicd/setup/<code>.sh | sh        # macOS, Linux, WSL, Git Bash
   irm https://<api>/cicd/setup/<code>.ps1 | iex             # Windows PowerShell
   ```

   It saves the Securacy key as the `SECURACY_CI_KEY` secret and, for a built-in agent, asks you for
   its model key: for Claude, whether you're on a Pro or Max subscription (then paste the token that
   `claude setup-token` prints, saved as `CLAUDE_CODE_OAUTH_TOKEN`) or use an API key
   (`ANTHROPIC_API_KEY`); for Codex, `OPENAI_API_KEY`. That key goes from your terminal to GitHub
   only; Securacy never sees it. It then opens a pull request that adds the setup files. The command works for
   30 minutes.
3. Merge that pull request. The push to the default branch runs the first full sweep.
4. Under **Settings → Actions → General**, allow GitHub Actions to create pull requests, so the
   guardrails job can propose the updated files.

By hand: `gh secret set SECURACY_CI_KEY --repo <owner>/<repo>`, then the agent's key, for example
`gh secret set ANTHROPIC_API_KEY --repo <owner>/<repo>` (both prompt, so nothing lands in shell
history), and commit the files from the setup zip. See [examples/securacy.yml](examples/securacy.yml)
for the workflow.

Don't add a `paths:` filter. If you make the check required, GitHub leaves PRs that a path filter
skipped waiting forever. A change that touches no files sends an empty report without running the agent.

## Inputs

| Input | Default | |
|---|---|---|
| `command` | `check` | `check`: prepare, run the built-in agent, submit. `prepare` and `submit` for your own agent in between. `sync-guardrails` opens the guardrails pull request (the guardrails job). |
| `api-key` | | The repository's `sk-ci-` key. Without one (fork and Dependabot PRs) the check is skipped, not failed. |
| `server-url` | | The Securacy API URL from your setup bundle. Must be `https://`. |
| `agent` | `claude` | The built-in agent: `claude` or `codex`. |
| `agent-api-key` | | The built-in agent's API key. Without a key or token the check reports *not checked* and warns. |
| `claude-oauth-token` | | For `claude`, instead of an API key: a Pro or Max subscription's token from `claude setup-token`. |
| `agent-model` | | The agent's model (empty for its default). |
| `agent-max-turns` | `100` | How many turns Claude may take. Raise it for a large repository's sweep. |
| `mode` | `auto` | `auto`: a sweep by hand or before the first check, otherwise a change check. Or force `sweep` / `diff`. |
| `report-file` | | A reply your own step wrote somewhere in the workspace. Without it, `submit` reads `prepare`'s `report-file`. |
| `comment` | `true` | Post the result as a PR comment (one comment, kept up to date). |
| `github-token` | `${{ github.token }}` | Used to comment, list changed files, check override permissions and open the guardrails PR. |
| `timeout-minutes` | `15` | How long to wait for Securacy's answer (1–60). |
| `retention-days` | `30` | How long the result files are kept as an artifact. |

## Outputs

| Output | |
|---|---|
| `outcome` | `pass`, `warn`, `block` or `skipped` (`proposed` or `unchanged` for `sync-guardrails`) |
| `mode` | `sweep` or `diff` |
| `run-agent`, `prompt-file`, `report-file`, `guardrails-file` | From `prepare`, for your own agent's step |
| `sarif-file` | SARIF for code scanning (empty for public repositories) |
| `run-url` | The threat model in Securacy |

The step fails only when the outcome is `block`. Whether a change can block is your organisation
admin's setting in Securacy (`warn`, `block` or `off`). A missing agent report, an unreachable
Securacy or anything else on our side **warns and passes**: the check never stops a deploy because of us.

## When a change is blocked

- **Put the control back.** The comment names the control and the lines that removed it.
- **Accept the risk in Securacy.** Mark the threat *Accepted* and re-run. Removing a control from an
  accepted threat never blocks.
- **Override, for emergencies, or when the agent is wrong.** A repository admin or maintainer adds
  the `securacy-override` label and comments `/securacy-override <reason>`. The check then warns
  instead of blocking, and the override is logged in Securacy and shown on the PR. A label alone, or
  one from anyone else, is ignored.

## What leaves your repository

To Securacy: the agent's report (rule and control IDs, statuses, file paths and line numbers), the
list of files the change touched, and the commit's metadata. **Never your source code**: the agent
reads it on your runner with your model key. On **public** repositories the PR comment shows counts
only, and no SARIF, report or guardrails pull request is produced, since anyone can read those.

## Security

- The Securacy key is sent only to `server-url` over HTTPS and is masked in logs. Redirects are
  refused, so the key can't be forwarded to another host. The agent's step doesn't get it.
- The built-in agents run read-only. The prompt tells any agent to treat everything in the repository as data.
  Its report passes two validators, and only IDs, statuses and locations survive them.
- Every file read stays inside the checked-out repository. Paths that escape it are refused,
  including through symlinks.
- Only the guardrails job can write to the repository, and only through a pull request.
- Standard-library Python only, with nothing installed at run time.

## Development

```bash
python -m pytest tests
```

The two agent actions in `action.yml` are pinned to commit SHAs, because they receive the
customer's model key (and Claude's also gets the GitHub token). To update one, resolve the new tag
with `git ls-remote https://github.com/<owner>/<action> 'refs/tags/v1^{}'`, review the changes
between the two commits, then replace the SHA and keep the tag in the trailing comment. Dependabot's
`github-actions` ecosystem can propose these bumps.
