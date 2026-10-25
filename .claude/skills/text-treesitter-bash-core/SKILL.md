---
name: text-treesitter-bash-core
description: "Architecture, data shapes, AST-walker quirks and the parse-error contract for Text::Treesitter::Bash. Load when parsing bash, extracting commands, touching the walker in Bash.pm, or reading what a rule sees."
---

# Text::Treesitter::Bash — core

Perl wrapper around `tree-sitter-bash 0.20.5`: parses bash source into an AST,
extracts executable commands, and runs a rule-based security checker over them —
primarily for AI-agent approval flows that classify raw bash before it runs.

Perl house conventions (`use` vs `require`, `$VERSION` = next, cpanfile pinning,
2-space indent, Changes) live in `getty-perl-core` — not restated here. Der
Kontrakt, den eine `Security::Rule` erfüllen muss, steht in
`text-treesitter-bash-rules`.

## Architecture

```
Text::Treesitter::Bash
├── parse($source)              -> Text::Treesitter::Tree
├── commands($source)           -> [@Command]      # walked AST, best effort on unparsable source
├── parse_errors($source)       -> [@ParseError]   # ERROR / MISSING regions
└── findings($source)           -> [@Finding]      # policy-light checks + parse errors

Text::Treesitter::Bash::Security::Checker
├── new(rules => [@RuleClass | $instance])
├── check_source($source)       -> [@Issue]        # parse + check + ParseError issues
└── check_commands(@Command)    -> [@Issue]        # rules only

Text::Treesitter::Bash::Security::Rule          (abstract base)
├── PathTraversal
├── DangerousFlags
├── SensitiveAccess
├── EnvDangerousVars
├── UnquotedExpansion
└── MissingAbsolutePath
```

Key files:
- `lib/Text/Treesitter/Bash.pm` — parser-walker + `findings`.
- `lib/Text/Treesitter/Bash/Security/Checker.pm` — rule registry, two check modes.
- `lib/Text/Treesitter/Bash/Security/Rule/*.pm` — one file per rule, subclass of `Rule`.
- `share/tree-sitter-bash/` — vendored upstream grammar 0.20.5 (`LICENSE`,
  `package.json`, `src/{parser.c,scanner.c,node-types.json}`), unmodified. At runtime
  it is copied into a tempdir (`_build_runtime_lang_dir`, `CLEANUP => 1`) and compiled
  at most once per process (`Text::Treesitter::Language::build`), shared by all
  instances. The tempdir is removed at process exit: nothing is cached across runs, so
  every process that parses pays the build.

## Data shapes

```perl
# Command (commands returns HashRefs):
{
  source     => 'rm -rf /tmp/x',
  command    => 'rm',                # basename, quotes stripped
  argv       => ['rm', '-rf', '/tmp/x'],
  start_byte => 17,
  end_byte   => 31,                  # exclusive
  context    => ['pipeline', ...],   # enclosing constructs
  before_op  => '&&',                # operator BEFORE this command (or undef)
  after_op   => '|'                  # operator AFTER this command (or undef)
}

# Finding (findings returns HashRefs):
{ type => 'shell_interpreter' | 'dynamic_shell' | 'shell_eval' | 'network_to_shell', ... }

# ParseError (parse_errors returns HashRefs; findings appends them last):
{ type => 'parse_error', message => ..., source => '"oops', start_byte => 5, end_byte => 10,
  missing => ')' }                   # missing only for a made-up token; then start == end, source ''

# Issue (Security::Checker returns HashRefs):
{ rule => 'DangerousFlags', severity => 'high' | 'medium' | 'low', message => ..., ... }
```

**Unparsable source fails closed.** tree-sitter never rejects input; it leaves `ERROR`
nodes or zero-width `MISSING` tokens, and the walker extracts only what still looks like
a command. `findings` and `check_source` therefore append every such region
(`parse_error` finding / `rule => 'ParseError'`, always `high`, no rule class behind it;
`Checker->new( parse_errors => 0 )` switches it off). "Empty list" must keep meaning
"parsed completely, nothing matched" — never drop these entries to make a result look
clean, and never add a path that returns before they are appended.

## Walker logic (`_walk_node` / `_walk_children` / `_walk_command_children`)

- Traverses top-down. Two walkers: the **statement walker** (`_walk_node` /
  `_walk_children`) emits entries and reads operators; the **expression walker**
  (`_walk_expression`) emits nothing, reads no operators (`|`, `||` in there are
  arithmetic/test operators) and only hands `command_substitution` /
  `process_substitution` back to the statement walker. Values go through the expression
  walker: `command_name`, prefix and statement-level `variable_assignment`, the children
  of `declaration_command` / `unset_command` / `test_command`, redirect targets, heredoc
  bodies. A new place where Bash runs a substitution → `_walk_expression`, never a bare
  `return` / `next`.
- **Nested commands are listed behind the entry they sit in**, one substitution level
  deeper. So `$commands->[-1]` is *not* "the previous command of this statement" — use
  `_last_command_at_level` for operators and redirect owners, and never pair list
  neighbours by index (`findings` scans back to the same level for `network_to_shell`).
- `heredoc_redirect` carries what follows the heredoc operator on the same line:
  arguments, redirects and — without left-hand side — the rest of a pipeline or list
  (`cat <<EOF | sh`). `_walk_heredoc_redirect` walks those and wires them to the heredoc's
  command.
- Context is pushed on `pipeline | subshell | negated | command_substitution |
  process_substitution` nodes, so every command inside a pipeline carries
  `context => [..., 'pipeline']`.
- Operator nodes (`&& || | |& ;` plus newline-as-`;`) are recognized from *unnamed*
  children. `_walk_children` writes `after_op` on `$commands->[-1]` as soon as it sees
  one, then walks the next child with `before_op` set to the same string. **Both the
  previous and following command get it** — `cmd1 && cmd2` → cmd1 `after_op=&&`,
  cmd2 `before_op=&&`.
- `findings` uses `before_op`/`after_op` to detect `network → shell` pipes.
- `command` is `_clean_word`-ed (whitespace + quote strip) for the **command name
  only**. `argv` entries are **raw** — may be quoted (`"foo"`, `'bar'`), contain
  whitespace, or be expansions like `$(cmd)`. Don't regex-match argv naively without
  considering quote context.
- `declaration_command` (`export X=Y`), `unset_command`, `test_command`
  (`[ ... ]`, `[[ ... ]]`) are emitted as `simple_command_entry`; argv is split on
  whitespace, losing quoting for compound assignments. Don't trust argv for these.

## Known gaps / traps

- Opaque grammar tokens (no node, no ERROR — nothing to walk): backticks in heredoc
  bodies, any substitution in a heredoc body starting with whitespace, backticks inside
  `${…}`, substitutions in `${x#…}` / `%` / `^^` / `,,` patterns. Listed as `todo` in
  `t/97_walker_coverage.t` and in the POD (`LIMITATIONS`).
- Arguments and file redirects written *behind* a heredoc operator (`rm <<EOF -rf /`,
  `cat <<EOF > /etc/passwd`) are not in `argv` / `redirects` — only substitutions in them
  are walked.
- Arguments still go through the statement walker, so an arithmetic `|` in an argument
  (`echo $((1|2))`) leaks into the command's `after_op`.
- Newline-as-`;` comes from the implicit-gap branch of `_walk_children`; the newline
  case in `_operator_text` is never reached (removing it changes nothing). Pinned in
  `t/40_edge_cases.t`.
- `|&` is in the operator set but `findings` does not special-case it.
- `time` and `!`-negation before a command extract with `context => ['negated']`, but
  no rule uses that yet.
- `EnvDangerousVars` / `UnquotedExpansion` regex-match `command->{source}`; quotes and
  whitespace in the node source can produce false positives — see `docs/CODE-ANALYSIS.md`.
- `Checker::check_source` uses `require Text::Treesitter::Bash;` — a `getty-perl-core`
  violation; should be a top-level `use`.

## Regeln

Der Kontrakt einer `Security::Rule`, die Severity-Stufen, die Muster und die Schritte
für eine neue Regel: `text-treesitter-bash-rules`.
