# CLAUDE.md

Guidance for Claude Code working in this repository.

`Text::Treesitter::Bash` is a Perl wrapper for `tree-sitter-bash 0.20.5`: it parses bash
source into an AST, extracts executable commands, and runs a rule-based security checker
over them — primarily for AI-agent approval flows that classify raw bash before it runs.

## Setup

```bash
sudo apt-get install -y libtree-sitter-dev   # system library, once (Debian/Ubuntu)
cpanm --installdeps .                         # Perl deps (reads cpanfile)
dzil build && dzil test                       # Dist::Zilla, [@Author::GETTY]
prove -lv t/                                  # or run the suite directly
```

Every process that parses compiles `tree-sitter-bash.so` from
`share/tree-sitter-bash/src/` into a `TMPDIR` tempdir once — slow per process (so per
test file), shared by all instances in it, removed at exit, not cached across runs.

## Delegation

Delegate behavior-relevant code to the right agent instead of touching it yourself —
the principle is a shared house rule (skilletor bundle `getty-cpan-dist@getty`); lanes
and hazards are in `.claude/rules/text-treesitter-bash-rules.md`.

| Task | Agent |
|---|---|
| Implement / refactor / debug walker, Checker, or Security::Rule::* | `text-treesitter-bash-worker` (default) |
| Commits, `Changes`, card → done, pre-release audit | `text-treesitter-bash-release-manager` |

The agents carry their knowledge via `briefing.skills` (see `.claude/agents/`); the main
agent delegates rather than loading them. Skill sources live under `.claude/skills/` —
the repo architecture, data shapes, walker quirks and rule contract are in
`text-treesitter-bash-core`; Perl house conventions in `getty-perl-core`. Ticket
coordination runs on the repo's `karr` board.
