# Text::Treesitter::Bash House Rules

The shared house rules come from skilletor — bundle `getty-cpan-dist@getty`: engineering
discipline, the delegation lock, the publish gate, karr coordination, CPAN release. They load
as `.claude/rules/.local.*.md`; if they are missing, run `skilletor sync` and publish nothing
until they load. This file adds what is true only here, and wins where it differs.

## What this repo is

Parse Bash with Text::Treesitter and extract executable commands, with a security `Checker`
over them. Read first: the walker in `Bash.pm`, the `Security::Rule` base, and neighbouring
rules.

## Agent team

| Task | Agent |
|---|---|
| Implement / refactor / debug walker, Checker, or rules | `text-treesitter-bash-worker` (default) |
| Commits, `Changes`, card → done, pre-release audit | `text-treesitter-bash-release-manager` |
| Read-only research, audit, gap analysis | `text-treesitter-bash-worker` ("read-only, change nothing") |

Behavior-relevant = the parser-walker, command extraction, `findings`, the security
`Checker`, the `Security::Rule::*` classes, their error handling, and the tests. Pure prose
docs and `Changes` notes are not.

## Hazards

- **Grammar is vendored, not a dependency.** `share/tree-sitter-bash/` is upstream 0.20.5,
  copied unmodified. It is compiled at runtime into a `TMPDIR` tempdir, once per process
  (removed at exit, not cached across runs); that touches no repo files. Never hand-edit
  `src/parser.c` / `src/scanner.c` — a grammar change is an upstream version bump.
- **argv is raw, `command` is cleaned.** The single trap behind most rule bugs: `argv` entries
  keep quotes/whitespace/expansions and `simple_command_entry` splits them on whitespace
  (losing quoting for `export X=Y`), while `command` is quote-stripped. A rule that
  regex-matches argv as if it were clean tokens produces false positives.

## Perl specifics — reference, don't restate

Module loading (`use` over `require`), `$VERSION` = next-unreleased, cpanfile pinning, 2-space
indent, `Changes`, and house style live in `getty-perl-core` (force-loaded for
`text-treesitter-bash-*` agents).
