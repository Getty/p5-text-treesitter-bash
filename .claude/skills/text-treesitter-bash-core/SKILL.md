---
name: text-treesitter-bash-core
description: "Architecture, data shapes, AST-walker quirks and the security-rule contract for Text::Treesitter::Bash. Load when parsing bash, extracting commands, adding or changing a Text::Treesitter::Bash::Security::Rule::*, or touching the walker in Bash.pm."
---

# Text::Treesitter::Bash — core

Perl wrapper around `tree-sitter-bash 0.20.5`: parses bash source into an AST,
extracts executable commands, and runs a rule-based security checker over them —
primarily for AI-agent approval flows that classify raw bash before it runs.

Perl house conventions (`use` vs `require`, `$VERSION` = next, cpanfile pinning,
2-space indent, Changes) live in `getty-perl-core` — not restated here.

## Architecture

```
Text::Treesitter::Bash
├── parse($source)              -> Text::Treesitter::Tree
├── commands($source)           -> [@Command]      # walked AST
└── findings($source)           -> [@Finding]      # policy-light checks

Text::Treesitter::Bash::Security::Checker
├── new(rules => [@RuleClass | $instance])
├── check_source($source)       -> [@Issue]        # parse + check
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
  it is copied into a tempdir (`_build_runtime_lang_dir`) and compiled once
  (`Text::Treesitter::Language::build`, `TMPDIR`-cachable). First run per machine is
  slow; later runs are fast if the compiled `.so` stays put.

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

# Issue (Security::Checker returns HashRefs):
{ rule => 'DangerousFlags', severity => 'high' | 'medium' | 'low', message => ..., ... }
```

## Walker logic (`_walk_node` / `_walk_children` / `_walk_command_children`)

- Traverses top-down; ignores `command_name` (it is extracted as `command`).
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

## Rule contract

Each rule is a **class method** `check($command)` returning a single Issue hash, an
array of Issues, or the empty list.

```perl
package Text::Treesitter::Bash::Security::Rule::YourRule;
# ABSTRACT: One-line description
our $VERSION = '0.002';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

sub check {
  my ( $class, $command ) = @_;
  return unless some_condition;
  return {
    rule     => 'YourRule',
    severity => 'low' | 'medium' | 'high',
    message  => "Human-readable explanation",
    command  => $command->{command},
    source   => $command->{source},
  };
}

1;
```

**Severities:** `low` (style/cosmetic), `medium` (footgun), `high` (likely exploit /
data loss). Critical does not exist — that is a policy decision above this layer.
Return a list for multiple issues; `Checker` flattens.

## Patterns to follow

- **Regex on argv** (`DangerousFlags`, `SensitiveAccess`, `PathTraversal`): iterate
  `@$argv`, `next if ref $arg`, skip quoted entries when needed.
- **Regex on source** (`EnvDangerousVars`, `UnquotedExpansion`): easier but loses AST
  structure; prefer when the rule is about surface text (`export LD_PRELOAD=...`).
  Watch out — `source` at the tree level spans operators/whitespace and can match
  across commands; scan `command->{source}` (trimmed to the node) for per-command
  isolation.
- **Severity scaling**: one rule returning different severities by context
  (`SensitiveAccess` — `/etc/shadow` high, `/dev/null` low).

## Adding a rule

1. Create `lib/Text/Treesitter/Bash/Security/Rule/YourRule.pm` per the contract.
2. Bump `$VERSION` in **all** files (`Bash.pm`, `Checker.pm`, every `Rule/*.pm`) to the
   next unreleased version (see `getty-perl-core`).
3. Add a test in `t/30_security.t` (one subtest per case, true + false positive where
   reasonable).
4. Update `Changes` with the new rule.
5. Update `docs/SECURITY-RESEARCH.md` (or a `docs/RULES.md` mapping rule → threat).

## Don't

- Don't reach into the tree-sitter Node API from a rule. The walker pre-extracts what
  you need; if a field is missing, **add it to the command hash in `_command_entry`**
  instead of calling `$node->text` in a rule.
- Don't `croak` from `check` — return an issue or empty list; a crash aborts the audit.
- Don't print. Return structured data.
- Don't use `ref` to detect quoted argv strings — quote handling is a tree-sitter
  concern; plumb a `quoted_argv` field if you need it.

## Known gaps / traps

- Newline-as-`;` is recognized in `_operator_text` but has no dedicated test.
- `|&` is in the operator set but `findings` does not special-case it.
- `time` and `!`-negation before a command extract with `context => ['negated']`, but
  no rule uses that yet.
- `EnvDangerousVars` / `UnquotedExpansion` regex-match `command->{source}`; quotes and
  whitespace in the node source can produce false positives — see `docs/CODE-ANALYSIS.md`.
- `Checker::check_source` uses `require Text::Treesitter::Bash;` — a `getty-perl-core`
  violation; should be a top-level `use`.
