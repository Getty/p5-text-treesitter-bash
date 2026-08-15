---
name: treesitter-bash-security
description: Use when adding/changing bash security rules, walking the tree-sitter AST, or extending Text::Treesitter::Bash::Security::Rule::* - establishes the rule contract, walker quirks, and existing patterns to follow
---

# Bash Security Rules — How to add one in this repo

## When this skill applies

You're about to:
- Add a new `Text::Treesitter::Bash::Security::Rule::*` class
- Modify the walker in `lib/Text/Treesitter/Bash.pm` (`_walk_node`, `_walk_children`, `_walk_command_children`, `_command_entry`, `_simple_command_entry`)
- Add new finding types in `Text::Treesitter::Bash::findings`
- Touch the share/tree-sitter-bash grammar (rare; usually upstream-only)

## Rule contract

Each rule is a **class method** `check($command)` returning either a single Issue hash, an array of Issues, or empty list.

```perl
package Text::Treesitter::Bash::Security::Rule::YourRule;
# ABSTRACT: One-line description
our $VERSION = '0.002';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

sub check {
  my ( $class, $command ) = @_;
  # $command is a HashRef as documented in CLAUDE.md
  return unless some_condition;
  return {
    rule     => 'YourRule',
    severity => 'low' | 'medium' | 'high',
    message  => "Human-readable explanation",
    # optional context fields you find useful:
    command  => $command->{command},
    arg      => $some_arg,
    source   => $command->{source},
  };
}

1;
```

**Severities:** `low` (style/cosmetic), `medium` (footgun), `high` (likely exploit / data loss). Critical doesn't exist — that's a policy decision above this layer.

**Multiple issues:** return a list. `Checker` flattens.

## Command hash fields you can rely on

| Field         | What it is                                                  |
|---------------|-------------------------------------------------------------|
| `source`      | Raw text of the AST node (incl. whitespace, quotes)         |
| `command`     | First word, basename-stripped, quotes-stripped              |
| `argv`        | ArrayRef of all arg texts, including command, **raw**       |
| `start_byte`  | Byte offset (not char offset)                               |
| `end_byte`    | Exclusive                                                   |
| `context`     | ArrayRef of enclosing nodes (e.g. `pipeline`, `subshell`)   |
| `before_op`   | `&&`, `||`, `|`, `|&`, `;`, `\n` or undef                   |
| `after_op`    | Same set, or undef                                          |

**argv caveat:** entries may be quoted (`"foo"`, `'bar'`), contain whitespace, or be raw expansions like `$(cmd)`. Don't regex-match them naively without considering quote context.

## Walker quirks to know

1. `command` always uses `_clean_word` (whitespace + quote-strip) for the **command name only**. Argv is raw.
2. `before_op` is the operator from the *previous* command's `after_op` — same string. So `cmd1 && cmd2`: cmd1 has `after_op=&&`, cmd2 has `before_op=&&`.
3. `_walk_children` writes `after_op` on `$commands->[-1]` as soon as it sees an ungenanntes child matching the operator set. Then it walks the next child with `before_op` set to that operator. **Both sides get it.**
4. `pipeline` context is pushed when entering a `pipeline` node, so every command inside a pipeline has `context => [..., 'pipeline']`.
5. `command_substitution` / `process_substitution` / `subshell` create nested commands — `findings` recurses via `commands` already, so a rule only sees one command at a time but the *callers* see the full tree.
6. `declaration_command` (`export X=Y`), `unset_command` (`unset X`), `test_command` (`[ ... ]`, `[[ ... ]]`) are emitted as `simple_command_entry` — argv is split on whitespace, which loses quoting for compound assignments. Caveat: don't trust argv for these.

## Existing patterns to follow

- **Pattern: regex on argv** (see `DangerousFlags`, `SensitiveAccess`, `PathTraversal`):
  ```perl
  for my $arg (@$argv) {
    next if ref $arg;          # defensive
    next if $arg =~ /^'/ && $arg =~ /'$/;  # skip quoted if needed
    ...
  }
  ```
- **Pattern: regex on source** (see `EnvDangerousVars`, `UnquotedExpansion`):
  - Easier, but loses AST structure. Prefer when the rule is about the surface text (e.g. `export LD_PRELOAD=...`).
  - Watch out: source includes operator/whitespace, can match across multiple commands. If you need per-command isolation, scan `command->{source}` (already trimmed to the node).
- **Pattern: severity scaling**: have a single rule that returns different severities depending on context (e.g. `SensitiveAccess` — `/etc/shadow` is `high`, `/dev/null` is `low`).

## Adding the rule

1. Create `lib/Text/Treesitter/Bash/Security/Rule/YourRule.pm` following the contract above.
2. Bump `$VERSION` in **all** files (`Bash.pm`, `Checker.pm`, all `Rule/*.pm`) to `0.003` (next-unreleased, see perl-core).
3. Add a test in `t/30_security.t` (one subtest per case, true + false positive where reasonable).
4. Update `Changes` with the new rule.
5. Update `docs/SECURITY-RESEARCH.md` or write a `docs/RULES.md` mapping rule → threat.

## Don't

- Don't reach into the tree-sitter Node API directly. The walker pre-extracts everything you need. If something's missing, **add a field to the command hash in `_command_entry`** instead of calling `$node->text` in a rule.
- Don't `croak` from `check`. Return an issue or empty list. Crashing aborts the whole audit.
- Don't print. Return structured data.
- Don't use `ref` to detect quoted strings in argv. Quote handling is a tree-sitter concern — if you need it, plumb a `quoted_argv` field through.
