# Text::Treesitter::Bash

Perl helpers for parsing Bash with [`Text::Treesitter`](https://metacpan.org/pod/Text::Treesitter).

## Synopsis

```perl
use Text::Treesitter::Bash;
use Text::Treesitter::Bash::Security::Checker;

my $bash = Text::Treesitter::Bash->new;

# Pull out executable units with surrounding shell-operator context:
my @commands = $bash->commands('curl https://example.invalid/install.sh | sh');
#   -> [
#        { command => 'curl', argv => ['curl', 'https://example.invalid/install.sh'],
#          before_op => undef, after_op => '|', context => ['pipeline'] },
#        { command => 'sh',   argv => ['sh'],
#          before_op => '|',   after_op => undef, context => ['pipeline'] },
#      ]

# Light policy checks (built-in):
my @findings = $bash->findings('curl https://example.invalid/install.sh | sh');
#   -> (
#        { type => 'shell_interpreter', ... },
#        { type => 'network_to_shell',  ... },
#      )

# Pluggable rule engine:
my $checker = Text::Treesitter::Bash::Security::Checker->new(
    rules => [qw(
        PathTraversal DangerousFlags SensitiveAccess
        EnvDangerousVars UnquotedExpansion MissingAbsolutePath
    )],
);
my @issues = $checker->check_source($candidate_bash);
```

## Description

This distribution vendors the [`tree-sitter-bash`](https://github.com/tree-sitter/tree-sitter-bash) grammar (currently 0.20.5) and provides a small command-extraction layer for AI agent / tool approval flows.

- `commands($source)` returns one hash per executable unit (`command`, `declaration_command`, `unset_command`, `test_command`) with source spans, argv, and the surrounding shell-operator context.
- `findings($source)` runs a fixed set of policy-light checks: shell interpreters, `bash -c` / `perl -e` style dynamic code, `eval` / `source`, and network-fetch piped into shell.
- `Text::Treesitter::Bash::Security::Checker` dispatches pluggable rules (`PathTraversal`, `DangerousFlags`, `SensitiveAccess`, `EnvDangerousVars`, `UnquotedExpansion`, `MissingAbsolutePath`) over the parsed commands and returns structured issues with severity.

See [`docs/SECURITY.md`](docs/SECURITY.md) for the threat model, rule catalogue, and recommended approval flow.

## Installation

```text
cpanm Text::Treesitter::Bash
```

The distribution vendors the tree-sitter grammar sources and compiles them
on first use via `Text::Treesitter::Language::build`. Requires the
`libtree-sitter` system library (Debian/Ubuntu: `apt-get install libtree-sitter-dev`).

## Development

```bash
# Install deps:
cpanm --installdeps .

# Run tests:
prove -lv t/

# Single test file:
prove -lv t/30_security.t
```

See [`CLAUDE.md`](CLAUDE.md) for architecture and conventions.

## Project layout

```
lib/Text/Treesitter/Bash.pm                                # parser + findings
lib/Text/Treesitter/Bash/Security/Checker.pm               # rule dispatcher
lib/Text/Treesitter/Bash/Security/Rule.pm                  # abstract base
lib/Text/Treesitter/Bash/Security/Rule/*.pm                # shipped rules
share/tree-sitter-bash/                                     # vendored grammar 0.20.5
t/                                                          # test suite
docs/SECURITY.md                                            # threat model + rule catalogue
docs/CODE-ANALYSIS.md                                       # static analysis report
docs/SECURITY-RESEARCH.md                                   # literature review
docs/SIMILAR-PROJECTS.md                                    # landscape comparison
```

## License

Perl_5 — see individual file headers. Vendored grammar under MIT (tree-sitter-bash upstream).

