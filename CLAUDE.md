# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Projekt

`Text::Treesitter::Bash` ist ein Perl-Wrapper für `tree-sitter-bash 0.20.5`. Zweck: Bash-Quelltext in einen AST parsen, daraus ausführbare Kommandos extrahieren und einen regelbasierten Security-Checker darüber laufen lassen — primär für AI-Agent-Approval-Flows, die rohen Bash-Input klassifizieren müssen, bevor er ausgeführt wird.

## Setup

```bash
# System-Library (einmalig, Debian/Ubuntu):
sudo apt-get install -y libtree-sitter-dev

# Perl-Dependencies (cpanm liest cpanfile):
cpanm --installdeps .

# Build/Install (Dist::Zilla, Author::GETTY):
dzil build
dzil test
dzil release   # nur mit Author-Rechten
```

## Tests

```bash
# Komplette Suite:
prove -lv t/

# Einzelne Datei:
prove -lv t/30_security.t

# Einzelner Subtest:
prove -lv t/30_security.t -- 'PathTraversal'
```

Der erste Lauf pro Maschine kompiliert die `tree-sitter-bash.so` aus `share/tree-sitter-bash/src/{parser.c,scanner.c}` via `Text::Treesitter::Language::build` in ein `tempdir` (`TMPDIR`-cachable). Folge-Läufe sind schnell, sofern die Datei dort liegen bleibt.

## Architektur

```
Text::Treesitter::Bash
├── parse($source)              -> Text::Treesitter::Tree
├── commands($source)           -> [@Command]      # walked AST
└── findings($source)           -> [@Finding]      # policy-light checks

Text::Treesitter::Bash::Security::Checker
├── new(rules => [@RuleClass | $instance])
├── check_source($source)       -> [@Issue]        # parse + check
└── check_commands(@Command)    -> [@Issue]        # nur rules

Text::Treesitter::Bash::Security::Rule          (abstract base)
├── PathTraversal
├── DangerousFlags
├── SensitiveAccess
├── EnvDangerousVars
├── UnquotedExpansion
└── MissingAbsolutePath
```

### Daten-Shapes

```perl
# Command (commands liefert HashRefs):
{
  source     => 'rm -rf /tmp/x',
  command    => 'rm',                # basename, quotes gestrippt
  argv       => ['rm', '-rf', '/tmp/x'],
  start_byte => 17,
  end_byte   => 31,
  context    => ['pipeline', ...],   # umgebende Konstrukte
  before_op  => '&&',                # Operator VOR diesem command (oder undef)
  after_op   => '|'                  # Operator NACH diesem command (oder undef)
}

# Finding (findings liefert HashRefs):
{ type => 'shell_interpreter' | 'dynamic_shell' | 'shell_eval' | 'network_to_shell', ... }

# Issue (Security::Checker liefert HashRefs):
{ rule => 'DangerousFlags', severity => 'high' | 'medium' | 'low', message => ..., ... }
```

### Walker-Logik (`_walk_node` / `_walk_command_children`)

- Traversiert top-down, ignoriert `command_name` (wird als `command` extrahiert).
- Kontext wird bei `pipeline | subshell | negated | command_substitution | process_substitution` pushed.
- Operator-Knoten (`&& || | |& ;` plus Newline) werden aus ungenannten Kindern erkannt; sie werden sowohl der **vorherigen** als auch der **folgenden** Command zugeordnet (siehe `before_op` / `after_op`).
- `findings` nutzt `before_op`/`after_op`, um `network → shell`-Pipes zu erkennen.

### Share-Verzeichnis

`share/tree-sitter-bash/` enthält den unveränderten Upstream-Grammar von `tree-sitter-bash 0.20.5` (`LICENSE`, `package.json`, `src/{parser.c,scanner.c,node-types.json}`). Zur Laufzeit wird das in ein Tempdir kopiert (siehe `_build_runtime_lang_dir`), einmalig kompiliert.

## Conventions (getty / perl-core)

- `use Module;` immer oben — kein `require` als Lazy-Optimization. Ausnahme: `Security::Checker::check_source` benutzt `require Text::Treesitter::Bash;` umgehen — Bug, sollte `use` werden.
- 2-space indent, kein Tab, keine trailing commas.
- `Path::Tiny` für File-IO, `Carp qw( croak )` für Fehler.
- Versionierung: `$VERSION` ist immer `next` (eine über CPAN). `cpanfile` pinnt gegen das **released** CPAN-`Text::Treesitter`, nicht gegen den Repo-Stand.
- Author-Plugin: `[@Author::GETTY]` (Dist::Zilla).

## Wichtige Dateien

- `lib/Text/Treesitter/Bash.pm` — Parser-Walker + `findings`.
- `lib/Text/Treesitter/Bash/Security/Checker.pm` — Rule-Registry, zwei Check-Modi.
- `lib/Text/Treesitter/Bash/Security/Rule/*.pm` — eine Datei pro Regel, Subclass von `Rule`.
- `share/tree-sitter-bash/` — vendored Grammar 0.20.5.
- `cpanfile` — Runtime + Test deps.
- `dist.ini` — Dist::Zilla (`[@Author::GETTY]`).
- `docs/SECURITY-RESEARCH.md` — was eine gute Bash-Security-Checker-Suite abdecken sollte.
- `docs/SIMILAR-PROJECTS.md` — Vergleich mit ähnlichen AI-Agent-Sandbox-Tools.
- `docs/CODE-ANALYSIS.md` — statische Code-Analyse (Edge-Cases, Bugs, neue Rules).

## Bekannte Lücken / TODOs

- Operator-Liste in `_operator_text` enthält Newline-als-`;` implizit — semantisch ok, aber kein dedizierter Test.
- `|&` (pipefail) wird im Operator-Set erkannt, aber in `findings` nicht speziell behandelt.
- `time`, `!`-Negation vor Command: Command wird mit `context => ['negated']` extrahiert, aber keine Security-Rule nutzt das aktuell.
- Mehrere Regeln matchen auf `command->{source}` mit regex (EnvDangerousVars, UnquotedExpansion). Bei tree-sitter-Node-Source mit Quotes/Whitespace können False-Positives entstehen — siehe `docs/CODE-ANALYSIS.md`.
- `check_source` in `Checker.pm` benutzt `require` — gegen perl-core, sollte `use` werden.
