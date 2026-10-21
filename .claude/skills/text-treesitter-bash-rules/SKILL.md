---
name: text-treesitter-bash-rules
description: "The contract a Text::Treesitter::Bash Security::Rule must fulfil, the severity levels, the proven rule patterns, the five steps to add a rule and the traps of rule code. Load when writing or changing a security rule, touching the Checker, or reviewing a rule."
---

# Text::Treesitter::Bash — Regeln

Der Vertrag, den eine `Security::Rule` erfüllen muss, die Muster, die sich bewährt
haben, und die Schritte für eine neue Regel. Architektur, Datenformen und die
Eigenheiten des AST-Walkers stehen in `text-treesitter-bash-core`.

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
