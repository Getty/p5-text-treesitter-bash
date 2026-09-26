# Text::Treesitter::Bash House Rules

Apply to every task in this repository unless explicitly overridden. Bias: caution over
speed on non-trivial work; use judgment on trivial tasks. Loaded automatically at launch
(same priority as `CLAUDE.md`). Subagents get their discipline from the skills
force-loaded via `briefing.skills` — this file is for the orchestrating agent.

## Engineering discipline

1. **Think before coding** — State assumptions. When uncertain, ask rather than guess.
   Present alternatives when ambiguous. Push back when a simpler approach exists.
2. **Simplicity first** — Minimum code that solves the problem. Nothing speculative.
3. **Surgical changes** — Touch only what you must. Don't "improve" adjacent code,
   comments, or formatting. Match existing style.
4. **Surface conflicts, don't average them** — Contradicting patterns: pick one (more
   recent / more tested), explain why, flag the other. Don't blend.
5. **Read before you write** — Before new code, read the walker in `Bash.pm`, the
   `Security::Rule` base, and neighbouring rules. "Looks orthogonal" is dangerous.
6. **Tests verify intent** — A rule test that can't fail when the logic changes is wrong.
   Reproduce a bug before fixing it; leave a regression subtest behind.
7. **Fail loud** — "Done" is wrong if anything was skipped silently. "Tests pass" is
   wrong if any subtest was skipped. Surface uncertainty, don't hide it.

## Delegation

This rule depends on whether the Agent/Task tool is available to you.

- **You can spawn subagents** (orchestrating main agent): Do NOT touch behavior-relevant
  code yourself — delegate to `text-treesitter-bash-worker`. Your lane: coordinate,
  inspect, plan, review diffs, run tests, edit non-behavioral docs. When in
  doubt, delegate. Why: only the `text-treesitter-bash-*` agents get their skills
  force-loaded via `briefing.skills`; you get no briefing and would touch internals with
  too little context. Specialist lanes:

  | Task | Agent |
  |---|---|
  | Implement / refactor / debug walker, Checker, or rules | `text-treesitter-bash-worker` (default) |
  | Commits, `Changes`, card → done, pre-release audit | `text-treesitter-bash-release-manager` |

- **You cannot spawn subagents** (you ARE a `text-treesitter-bash-*` agent): The
  delegation lock does not apply — implement, refactor, debug, and test per these rules.

Behavior-relevant = the parser-walker, command extraction, `findings`, the security
`Checker`, the `Security::Rule::*` classes, their error handling, and the tests. Pure
prose docs and `Changes` notes are not.

**Only `text-treesitter-bash-release-manager` commits.** A worker leaves a commit-ready tree and hands its card
to `review`; you then dispatch `text-treesitter-bash-release-manager` to cut the commit and close the card.

## Coordination — karr board (always in scope)

Ticket coordination is the orchestrating agent's job, so `karr` is always in scope — just
use it, no need to invoke the `kanban-issues-karr-coordination` skill first. Git-native kanban;
state lives in `refs/karr/*`; this repo has its own board.

- `karr list --compact` / `karr board` — open work · `karr show ID` — detail
- `karr create "Title" --priority high --body '…'` — new ticket
- `karr move ID in-progress --claim NAME` · `karr handoff ID --claim NAME --note "…"`
- mutating commands auto-sync; `karr sync --pull|--push` for explicit exchange

**Serialize board mutations when fanning out.** Keep implementation parallel if you like,
but collect results and then loop `karr move`/`handoff`/`sync` sequentially — N of them
landing at once is a resource event, not a cheap command.

## Release — never without permission

`dzil build` / `dzil test` / `prove` are fine anytime. `dzil release` and any upload are
STRICTLY forbidden without the maintainer's explicit go-ahead — even if a plan or STATUS
document lists "release" as the next step. Stop and ask.

The CPAN release state of a dependency is never a blocker and never a ticket: the repo
`$VERSION` is always one ahead of CPAN, and coupled distributions are released together.
Only the local working-tree state counts when reasoning about what is "done".

## Project hazards

- **Grammar is vendored, not a dependency.** `share/tree-sitter-bash/` is upstream
  0.20.5, copied unmodified. It is compiled once at runtime into a `TMPDIR` tempdir; the
  first test run per machine is slow and touches no repo files. Never hand-edit
  `src/parser.c` / `src/scanner.c` — a grammar change is an upstream version bump.
- **argv is raw, `command` is cleaned.** The single trap behind most rule bugs: `argv`
  entries keep quotes/whitespace/expansions and `simple_command_entry` splits them on
  whitespace (losing quoting for `export X=Y`), while `command` is quote-stripped. A rule
  that regex-matches argv as if it were clean tokens produces false positives.

## Perl specifics — reference, don't restate

Module loading (`use` over `require`), `$VERSION` = next-unreleased, cpanfile pinning,
2-space indent, `Changes`, and house style live in `getty-perl-core` (force-loaded for
`text-treesitter-bash-*` agents). Do not duplicate that content here.
