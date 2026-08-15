# Code-Analyse: Text::Treesitter::Bash

Stand: 2026-08-15
Codebase-Stand: v0.002 (repo, un-released) / v0.001 (CPAN)
Verwandte Skills: `.claude/skills/perl-core/SKILL.md`, `.claude/skills/treesitter-bash-security/SKILL.md`

Befunde sind nummeriert und tragen ein Suffix fuer den Schweregrad:

- **BUG** — funktional falsch / Sicherheitsproblem / silent data loss
- **ENHANCEMENT** — sinnvolle Erweiterung die das Verhalten klarer / besser macht
- **NIT** — Stil / Doku / micro

Alle Zeilenangaben beziehen sich auf den aktuellen Commit (`33d5e82`).

---

## 1. Architektur-Ueberblick

```
+------------------+       parse() / commands()        +-----------------------+
|  Quelltext       |---------------------------------->| Text::Treesitter::Bash|
|  (Skalar-String) |                                   |  lib/.../Bash.pm      |
+------------------+                                   |  - parse              |
                                                       |  - commands           |
                                                       |  - findings           |
                                                       |  - _walk_node         |
                                                       |  - _command_entry     |
                                                       +-----------+-----------+
                                                                   |
                                       commands()  ------+         | findings()
                                                                 |
                                                       +---------v---------+
                                                       |  Command-Liste    |
                                                       |  (Array of Hashes)|
                                                       +---+----------+----+
                                                           |          |
                                       check_commands() ---+          +-- (eingebaut)
                                                           |
                                          +----------------v------------------+
                                          | Security::Checker                 |
                                          | lib/.../Security/Checker.pm       |
                                          |  - new(rules => [...])             |
                                          |  - check_source(source)  --calls--+--> Bash->commands
                                          |  - check_commands(@cmds)          |
                                          |      +--- Rule::*->check($command)|
                                          +----------------+------------------+
                                                           |
                                       +-------------------+------------------+
                                       |                   |                  |
                              Rule::PathTraversal   Rule::DangerousFlags   Rule::... |
```

### Datenfluss

**Pfad A (eingebaute Findings):**
```
source --[Bash::findings]--> commands --[findings()]--> List<Finding{type,message,command}>
                                          |
                                          +-- pro Command: shell_interpreter / dynamic_shell / shell_eval
                                          +-- pro Paar:       network_to_shell
```

**Pfad B (Plugin-Rules):**
```
source --[Bash::commands]--> commands
       --[Checker::check_source]--> check_commands(@commands)
                                  |
                                  +-- Rule::PathTraversal->check($cmd) -> [Finding]
                                  +-- Rule::DangerousFlags->check($cmd) -> Finding|undef
                                  +-- Rule::SensitiveAccess->check($cmd) -> Finding|undef
                                  +-- Rule::EnvDangerousVars->check($cmd) -> Finding|undef
                                  +-- Rule::MissingAbsolutePath->check($cmd) -> Finding|undef
                                  +-- Rule::UnquotedExpansion->check($cmd) -> [Finding]
```

### Bewertung

- **Zwei parallele Finding-Pipelines** mit unterschiedlichen Datenformaten (siehe §7).
  Eingebaute Findings (`shell_interpreter`, `dynamic_shell`, `shell_eval`,
  `network_to_shell`) sind hartcodiert in `Bash.pm`. Alle anderen Regeln
  leben als Plugin-Klassen in `Security/Rule/`. Die Trennlinie ist
  nicht dokumentiert und fuehrt zu Verwirrung: warum ist `network_to_shell`
  eingebaut, `unquoted_expansion` aber ein Plugin?
- **Command-Hash ist gut dokumentiert** (siehe treesitter-bash-security Skill §"Command
  hash fields"). Regeln verlassen sich darauf.
- **Rule.pm** ist eine reine ABC-Klasse; `Checker.pm` laedt Plugin-Klassen
  per `Module::Load::load()` zur Laufzeit. Das ist die einzige Stelle,
  an der ein wirklicher "runtime plugin load" legitim waere (perl-core erlaubt
  das fuer dynamische Klassennamen aus Konfig / DB). Aber siehe §3.1.

---

## 2. Korrektheits-Probleme

### 2.1 Eingebaute Findings (`Bash.pm`)

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 2.1.1 | `lib/Text/Treesitter/Bash.pm` | 76 | BUG | `network_to_shell` matcht nur `^\|` — also nur die normale Pipe. **`|&` (pipe-failure, bash-spezifisch) wird NICHT erkannt.** `curl https://x \|& sh` ist exakt so gefaehrlich wie `curl https://x \| sh`. Empfehlung: `( $left->{after_op} // '' ) =~ m/^\|(?:&)?/` bzw. explizit `|\|`. |
| 2.1.2 | `lib/Text/Treesitter/Bash.pm` | 38-89 | ENHANCEMENT | `findings()` dupliziert Logik, die eigentlich eine Rule sein sollte (`shell_interpreter`, `dynamic_shell`, `shell_eval`, `network_to_shell`). Empfehlung: Diese vier Finding-Typen in `Security/Rule/*` ziehen und `findings()` zu einem Thin-Wrapper machen, der die Rule-Sammlung automatisch mit ein paar Default-Rules bestueckt. Macht die Architektur konsistent: ein Mechanismus, eine Stelle. |
| 2.1.3 | `lib/Text/Treesitter/Bash.pm` | 72 | BUG | `for my $index ( 1 .. $#commands )` — bei leerer Source ist `$#commands == -1`, der Range `1..-1` ist in modernem Perl leer (gut), aber in 5.26..5.34 war er `[1, 0]`. Kein sofortiger Crash, aber fragil. Empfehlung: `for my $index ( 1 .. scalar(@commands) - 1 )` oder expliziter Guard. |
| 2.1.4 | `lib/Text/Treesitter/Bash.pm` | 55-61 | BUG | `_is_dynamic_shell` prueft `-c` fuer Perl/Ruby/Node (richtig ist `-e`), aber: Perl kennt auch `-E`, `-p`, `-n`, `-i`, `-pe`, `-ne`; Ruby kennt `-e`, `-r` (verwandt mit require), `-rr`; Python kennt `-c` (gut) plus `-m` (Modul-Ausfuehrung). `perl -e 'rmtree "/"'` wird erkannt, aber `perl -E 'say `rmtree "/"`'` nicht. Empfehlung: Whitelist erweitern. |
| 2.1.5 | `lib/Text/Treesitter/Bash.pm` | 375-389 | BUG | `_is_dynamic_shell` matcht `python` aber **nicht** `python3.11`, weil das Regex `\Apython(?:\d+(?:\.\d+)?)?\z` kein `python3.11rc1`-Suffix akzeptiert (kein Real-World-Issue), aber `pypy`, `pypy3`, `jython`, `micropython`, `nushell` (nu) sind ebenfalls Python-OSVs. Empfehlung: Liste explizit fuehren statt Regex-Whitespace. |
| 2.1.6 | `lib/Text/Treesitter/Bash.pm` | 47 | NIT | `_is_shell_interpreter` enthaelt `fish` — gut — aber `csh`, `tcsh`, `ash`, `busybox sh` fehlen. NIT, weil diese selten via `-c` benutzt werden, aber `csh -c 'rm -rf /'` ist ebenfalls gefaehrlich. |
| 2.1.7 | `lib/Text/Treesitter/Bash.pm` | 271-283 | BUG | `_simple_command_entry` splittet den Source-Text blind auf Whitespace: `export FOO="hello world"`. Daraus wird `argv = ['export', 'FOO="hello', 'world"']`. `command` ist `export`, argv ist kaputt. Regeln, die `argv` regexen, koennen `FOO="hello world"` nicht korrekt analysieren (siehe `EnvDangerousVars`, die auf `source` regexen — gut — aber jeder Rule, der auf `argv` baut, kriegt kaputte Tokens fuer compound assignments). Empfehlung: AST-Werte aus dem Tree holen statt String-Split, oder den Tree-sitter-`word`-Knoten fuer jedes Argument verwenden. |

### 2.2 Walker (`_walk_node`, `_walk_children`, `_walk_command_children`)

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 2.2.1 | `lib/Text/Treesitter/Bash.pm` | 173-176 | BUG | `subshell`, `process_substitution`, `command_substitution` werden mit `initial_before_op = undef` an `_walk_children` weitergegeben. **Der Operator VOR dem subshell geht verloren.** Beispiel: `cmd1 && (cmd2; cmd3)` — `cmd2` bekommt `before_op = undef`, obwohl es faktisch hinter `&&` steht. Empfehlung: `initial_before_op` aus dem `pending_op` des aeusseren `_walk_children` durchreichen. |
| 2.2.2 | `lib/Text/Treesitter/Bash.pm` | 183-186 | NIT | `negated_command` setzt context `'negated'`, aber die Negation `!` selbst wird nirgends im Command-Hash abgebildet. Wer `! rm -rf /` erkennen will, muss auf context-String matchen, was fragil ist. Empfehlung: `negated => 1` im Hash. |
| 2.2.3 | `lib/Text/Treesitter/Bash.pm` | 188-194 | BUG | `redirected_statement` behandelt nur `body`. Die Redirects (`>`, `<`, `>>`, `<<<`, `2>&1`) gehen verloren. Empfehlung: Redirects als `redirects => [...]` ans Command-Hash anhaengen — Regeln wie `WritingToSystemPath` koennten dann `> /etc/passwd` erkennen. |
| 2.2.4 | `lib/Text/Treesitter/Bash.pm` | 167-171 | NIT | `declaration_command`, `unset_command`, `test_command` werden via `_simple_command_entry` emittiert. `test_command` (`[ ... ]`, `[[ ... ]]`) ist KEIN ausfuehrbares Kommando — es ist eine Bedingungsauswertung. In eine Finding-Liste gehoert das eigentlich nicht. Empfehlung: `test_command` ueberspringen oder mit `context => ['test']` markieren und Regeln beibringen, es zu ignorieren. |
| 2.2.5 | `lib/Text/Treesitter/Bash.pm` | 220-228 | NIT | `_walk_command_children` filtert `command_name` raus, aber nicht `variable_assignment` (z.B. `FOO=bar cmd`). Dadurch entstehen leere Subtrees. Funktioniert zufaellig (kein neues Command wird gepusht), aber suboptimal. |
| 2.2.6 | `lib/Text/Treesitter/Bash.pm` | 297-308 | BUG | `_operator_text` kennt `&& \|\| \| \|& ; \n`. **Es fehlt `&` (Background).** Beispiel: `rm -rf / & sleep 5` — `rm` bekommt kein `after_op='&'`. Empfehlung: `return $text if $text eq '&';` hinzufuegen. |
| 2.2.7 | `lib/Text/Treesitter/Bash.pm` | 305 | NIT | `return ';' if $text =~ m/^\s*\n\s*$/;` — das ist eigentlich ein Newline-Operator. Es waere klarer, das Literal `'\n'` zurueckzugeben statt `';'`, weil Newlines in Listen wirklich als Command-Separator wirken. Konsistenz: es gibt zwei Werte fuer den gleichen Sachverhalt. |
| 2.2.8 | `lib/Text/Treesitter/Bash.pm` | 156-197 | ENHANCEMENT | Keine spezialisierte Behandlung fuer `case_statement`, `for_statement`, `while_statement`, `if_statement`, `function_definition`, `elif_clause`, `else_clause`, `do_group`. Sie fallen durch auf `_walk_children`. Funktioniert (innere Commands werden extrahiert), aber `context` verliert diese wichtigen Marker. Empfehlung: Dedizierte Branches, die `context` ergaenzen (analog zu `'pipeline'`). |
| 2.2.9 | `lib/Text/Treesitter/Bash.pm` | 156-197 | ENHANCEMENT | `function_definition` wird nicht speziell behandelt. Der Funktionsname `foo` aus `foo() { bar; }` geht verloren. Empfehlung: `function_definition`-Branch mit Funktionsnamen-Extraktion. |

### 2.3 `_command_entry`

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 2.3.1 | `lib/Text/Treesitter/Bash.pm` | 230-265 | BUG (potentiell) | Das `shift @fields`-Paar-Pattern nimmt an, dass `field_names_with_child_nodes` strikt alternierend `(field_name, child_node)`-Paare liefert. Wenn der Binding-Aufruf eine ungerade Anzahl liefert, oder wenn die Paar-Struktur sich bei einem Update aendert, dann wird die Zuordnung korrupt: das naechste `child` kommt aus dem falschen Feld. Empfehlung: Iteriere explizit ueber `$node->field_names` und hole das Child per `$node->child_by_field_name($field)`. Vermeidet die Annahme ueber die Pair-Struktur und ist robuster. |
| 2.3.2 | `lib/Text/Treesitter/Bash.pm` | 248-250 | BUG | Unfielded-children-Logik captured alles, was `_is_argument_node` matcht UND NACH dem Namen kommt (`$seen_name`). Aber tree-sitter kann auch unbenannte `word`-Kinder VOR dem Namen haben (z.B. bei `env VAR=val cmd` — wenn `env` als unbenanntes `word` VOR `command_name` kommt). Diese werden dann verschluckt. Empfehlung: Nur `argument`-Feld-Iteration verwenden; unbenannte Kinder ganz wegwerfen oder als Meta sammeln. |
| 2.3.3 | `lib/Text/Treesitter/Bash.pm` | 310-324 | BUG | `_is_argument_node` enthaelt nicht: `array`, `subscript`, `regex`, `extglob_pattern`. `${arr[@]}` wird als Argument stillschweigend fallengelassen. Konsequenz: `cat ${arr[@]}` hat `argv = ['cat']` statt `['cat', '${arr[@]}']`. Regeln wie `UnquotedExpansion` koennen das nicht sehen. Empfehlung: Tree-sitter-bash node-types.json konsultieren und vollstaendige Liste fuehren. |
| 2.3.4 | `lib/Text/Treesitter/Bash.pm` | 326-338 | BUG | `_clean_word` strippt `"..."` und `'...'` Quotes, aber: bei `'$foo'` (single-quoted, also literal `$foo`) wird `$foo` zurueckgegeben. Wer `command` als Bare-Namen verwendet, kriegt ein Dollarzeichen — fuehrt zu Regex-Fehltreffern in `KNOWN_COMMANDS` und Rule-Logik. Empfehlung: Quoted-Words als separate Klasse behandeln (siehe treesitter-bash-security Skill §"argv caveat"). |

### 2.4 Edge-Cases ohne Behandlung

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 2.4.1 | `lib/Text/Treesitter/Bash.pm` | 23-27 | BUG | `parse()` akzeptiert nur `defined $source`. Leerstring `""` ist erlaubt (gut), aber: nil-bytes (`"\0"`) im Source fuehren vermutlich zu Tree-sitter-internem Fehler, weil tree-sitter byte-orientiert ist und die meisten Grammars NUL ablehnen. Invalid UTF-8 (`"\xff"`) ohne `utf8::decode` ebenfalls. Keine Validierung, keine `croak`. Empfehlung: Mindestens UTF-8-Validierung via `utf8::valid($source)` und ein klarer Fehler. |
| 2.4.2 | `lib/Text/Treesitter/Bash.pm` | 113-139 | NIT | `_build_runtime_lang_dir` extrahiert 5 Dateien in einen `tempdir` mit `CLEANUP => 1`. Das ist OK, aber: der `tempdir`-Pfad landet in `$self->{_tmpdir}` und wird nirgends genutzt. Toter State. Empfehlung: Entweder weglassen oder den Pfad ueber eine `Accessor` exponieren (Debugging). |
| 2.4.3 | `lib/Text/Treesitter/Bash.pm` | 99-104 | NIT | `Text::Treesitter::Language::build` wird ohne explizite Fehlerbehandlung aufgerufen. Bei Compile-Failure faengt der `local *STDOUT = $capture` die Diagnose ab — die aber nur in `$stdout` landet und nirgends sichtbar wird. Empfehlung: Bei `! -f $lang_lib` nach `build` immer noch `croak` mit `$stdout`, sonst ist der Build-Fehler unsichtbar. |
| 2.4.4 | `lib/Text/Treesitter/Bash.pm` | 141-154 | NIT | `_find_share_dir` schaut zuerst `dist_dir()`, dann `$INC`-basiert. Wenn beides scheitert, wird gecroaked. Aber: bei der `INC`-Variante wird `parent(4)` benutzt, was magisch ist und bei Package-Restrukturierung bricht. Empfehlung: konkreten Pfad berechnen (`path(__FILE__)->parent(3)->child('share')` analog zu anderen Getty-Dists). |

### 2.5 Bugs in den Regeln

#### DangerousFlags

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 2.5.1 | `lib/Text/Treesitter/Bash/Security/Rule/DangerousFlags.pm` | 8-14 | BUG (dead code) | `%DANGEROUS_FLAGS` wird definiert aber **nirgends gelesen**. Die eigentliche Logik lebt in den `if`-Ketten unten. Empfehlung: entweder `%DANGEROUS_FLAGS` als Lookup-Tabelle benutzen (DRY) oder loeschen. |
| 2.5.2 | `lib/Text/Treesitter/Bash/Security/Rule/DangerousFlags.pm` | 22-58 | BUG | Nur `rm` / `mv` / `cp` sind sinnvoll mit `-rf`. Aber die Rule feuert fuer **jeden** Command. `gcc -f foo` wuerde als `-rf`-Variante getriggert wenn `-r` vorhanden waere. Mit der `next if ref $arg`-Logik wird zwar ueberprueft, aber die Rule kennt nicht den Command — `ls -rf` wuerde ebenfalls als "dangerous combination: -rf" reportet werden. Empfehlung: Whitelist von Commands, fuer die `-rf`/`-fr`/`--force` mit `--recursive` tatsaechlich destruktiv ist (rm, mv, cp, find -delete, chmod -R ...). |
| 2.5.3 | `lib/Text/Treesitter/Bash/Security/Rule/DangerousFlags.pm` | 35-44 | BUG | Die Rule prueft auf `-r \|\| -R \|\| --recursive`, aber `rm -fr` (umgekehrte Reihenfolge) wird **nicht** erkannt: Argumente werden in der Reihenfolge der Argv-Liste geprueft, und bei `-fr` ist `$arg` gleich `-fr`, was den ersten `if`-Zweig matched — ok, das matched. Aber `rm -fR` (gross R) matcht weder `-r` noch `-R` (gross vs klein unterscheidet die if-Kette). Empfehlung: case-insensitive regex `qr/-[rR]\|--(?:recursive\|force)/`. |
| 2.5.4 | `lib/Text/Treesitter/Bash/Security/Rule/DangerousFlags.pm` | 35 | BUG | `-R` als Grossbuchstabe matched, aber `-RF` (kombiniert) oder `-FR` matched nicht, weil `$arg` exakt gleich sein muss. Empfehlung: zusammengesetzte Argumente parsen. |

#### PathTraversal

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 2.5.5 | `lib/Text/Treesitter/Bash/Security/Rule/PathTraversal.pm` | 16 | BUG | Regex `(?:\.\./\|/etc/../\|/proc/../\|/sys/../)` erwischt `../` nur am Anfang **eines Path-Segments**, das hartcodiert `/etc/../` direkt davor haben muss. `cat /etc/foo/../shadow` (das ist die echte Traversal-Form, weil nach `foo/..` zurueck nach `etc` geht) wird **NICHT** gematcht. Empfehlung: `\.\.(?:/\|$)` reicht — jedes `..` ist verdächtig, nicht nur die hartcodierten Praefixe. |
| 2.5.6 | `lib/Text/Treesitter/Bash/Security/Rule/PathTraversal.pm` | 26 | BUG | `(?:\A\|\s)(/proc/self\|/proc/\$\$\|/sys/fs)` — `\A` matched am String-Anfang. Fuer `cat /proc/self/maps` ist `cat ` davor (Space). Der Anchor `\A\|\s` trifft vor `cat ` nicht zu, weil `\A` am Anfang ist und `\s` nach `cat ` zaehlt. Also muss der Match direkt nach einem Whitespace oder am Anfang sein. Das funktioniert fuer `/proc/self/...` als eigenes Arg, aber `cat "-flag" /proc/self` matched wegen Whitespace davor. Verwirrend: zwei separate Branches die das gleiche Problem haben, doppelt unnoetig. Empfehlung: Vereinheitlichen. |

#### UnquotedExpansion

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 2.5.7 | `lib/Text/Treesitter/Bash/Security/Rule/UnquotedExpansion.pm` | 14 | BUG (false negative) | `$source !~ m{".*\$[a-zA-Z_]}` schliesst die ganze Source aus der Pruefung aus, sobald **irgendein** doppelt-gequoteter Variablen-Wert existiert. Beispiel: `echo "safe $foo" $bar/baz` — der negative Match sieht `"safe $foo"` und matched; die Rule ueberspringt ALLES, also wird `$bar/baz` (das gefaehrliche) nicht gemeldet. Empfehlung: per-Variable pruefen, nicht per-Source. |
| 2.5.8 | `lib/Text/Treesitter/Bash/Security/Rule/UnquotedExpansion.pm` | 14 | BUG (false negative) | Doppel-quoted String mit Variablen OHNE Slash-Danach wird auch nicht entdeckt. Aber das ist hier OK weil es nicht das Ziel ist. Jedoch: `${var}` und `$((...))` werden nicht gematcht (`$` gefolgt von `(`, `(`, oder `{`). Empfehlung: Pattern erweitern. |
| 2.5.9 | `lib/Text/Treesitter/Bash/Security/Rule/UnquotedExpansion.pm` | 14 | BUG (false positive) | Single-Quoted Strings wie `echo '$foo'` enthalten `$foo`, aber in single-quotes wird NICHT expandiert. Die Rule meldet das trotzdem als Risiko, weil sie `$foo` als bare findet. Empfehlung: Single-Quote-Kontext in der Source pruefen, oder auf den Tree-sitter-AST gehen (siehe treesitter-bash-security Skill §"Don't use ref to detect quoted strings"). |
| 2.5.10 | `lib/Text/Treesitter/Bash/Security/Rule/UnquotedExpansion.pm` | 22 | NIT | `substr($source, $pos + length($var), 1)` schaut nur 1 Zeichen nach dem Variablennamen. Wenn dort `} ` steht (`${var}`), dann trifft das nicht. Aber `$var}` als bare-Name matcht das Regex `\$[a-zA-Z_][a-zA-Z0-9_]*` garnicht. Edge-Case. |
| 2.5.11 | `lib/Text/Treesitter/Bash/Security/Rule/UnquotedExpansion.pm` | 23 | NIT | `m{[/\-\.]}` — Punkt wird auch getriggert, was bei `echo "$var.txt"` Sinn ergibt (Word-Splitting via IFS). Aber bei `echo "$var."` (Argument mit Punkt am Ende) ist das oft gewollt. Schwellwert-Sache. |

#### EnvDangerousVars

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 2.5.12 | `lib/Text/Treesitter/Bash/Security/Rule/EnvDangerousVars.pm` | 27 | BUG (false positive) | `\b(?:export\s+)?\Q$var\E\b` — der `export`-Praefix ist optional, matched also auch `MY_LD_PRELOAD_TEST=foo`. Dank `\b` (Word-Boundary) greift das nur, wenn das letzte Zeichen von `$var` (z.B. `D` in `LD_PRELOAD`) nicht von einem Wortzeichen gefolgt wird. Aber `MY_LD_PRELOAD` endet auf `D`, das `_` davor ist Wortchar — `\b` dazwischen matched nicht. Also OK. Aber: `LD_PRELOAD_X` wuerde nicht matchen, weil `_` Wortzeichen ist. Korrekt. Edge-Case-Pass. |
| 2.5.13 | `lib/Text/Treesitter/Bash/Security/Rule/EnvDangerousVars.pm` | 8-17 | ENHANCEMENT | Die Liste ist klein. Was fehlt: `PYTHONPATH` (Arbitrary-Code-Injection via `python`), `NODE_PATH` (analog), `PERL5LIB` / `PERL5OPT` (Perl Prepend und `-M` Flag), `RUBYLIB` / `RUBYOPT`, `IFS` (Word-Splitting), `PS4` (Debug-Source-Trigger in `set -x`), `PROMPT_COMMAND`, `SHELLOPTS`, `BASH_FUNC_*` (exportable Bash-Functions ab Bash 4.0). |

#### SensitiveAccess

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 2.5.14 | `lib/Text/Treesitter/Bash/Security/Rule/SensitiveAccess.pm` | 8-19 | BUG (false positive) | `/dev/` matched `/dev/null`, `/dev/zero` etc. — was extrem haeufig benutzt wird (`echo > /dev/null`, `dd if=/dev/zero`). Severity ist `low`, also nicht kritisch, aber `/dev/null` als "Device file access" mit niedriger Severity ist irrefuehrend. Empfehlung: Whitelist fuer `/dev/null`, `/dev/zero`, `/dev/std{in,out,err}`, `/dev/urandom`, `/dev/random`, `/dev/tty`. |
| 2.5.15 | `lib/Text/Treesitter/Bash/Security/Rule/SensitiveAccess.pm` | 8-19 | ENHANCEMENT | Patterns sind sehr Unix-zentriert. Was fehlt: macOS Keychain, Windows-Pfade, Container-relevant (`/var/run/docker.sock`), Kernel-Module (`/lib/modules/`), Browser-Profiles (`~/.config/google-chrome/`), GnuPG (`~/.gnupg/`), `~/.netrc`, `~/.pgpass`. |

#### MissingAbsolutePath

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 2.5.16 | `lib/Text/Treesitter/Bash/Security/Rule/MissingAbsolutePath.pm` | 8-12 | BUG (false positive) | `%KNOWN_COMMANDS` ist handgepflegt. Fehlt: **Shell-Builtins** (`cd`, `pwd`, `echo`, `printf`, `read`, `test`, `[`, `[[`, `exit`, `return`, `set`, `unset`, `declare`, `typeset`, `local`, `export`, `eval`, `exec`, `source`, `.`, `alias`, `unalias`, `hash`, `type`, `command`, `builtin`, `shift`, `getopts`, `trap`, `wait`, `jobs`, `fg`, `bg`, `kill`, `logout`, `times`, `ulimit`, `umask`, `help`, `history`, `pushd`, `popd`, `dirs`, `shopt`, `complete`, `compgen`, `mapfile`, `readarray`). Jeder Aufruf eines Builtins ohne absoluten Pfad wird falsch positiv gemeldet. Empfehlung: Shell-Builtin-Whitelist hinzufuegen. |
| 2.5.17 | `lib/Text/Treesitter/Bash/Security/Rule/MissingAbsolutePath.pm` | 27-34 | BUG | Wenn der Name nicht mit `[a-zA-Z_]` startet (also z.B. `1foo`, `(foo)`, `[foo]`), wird ein Finding generiert — aber das sind oft syntaktische Konstrukte, nicht Kommandos. Empfehlung: `return` ohne Finding fuer Namen die nicht mit `^[a-zA-Z_][a-zA-Z0-9_+\-.]*$` matchen. |
| 2.5.18 | `lib/Text/Treesitter/Bash/Security/Rule/MissingAbsolutePath.pm` | 19-21 | NIT | `return if $name =~ m{/}` — Command mit Slash aber nicht absolut (`./script.sh`, `../bin/cmd`, `subdir/cmd`) wird uebersprungen. OK fuer `./` und `../` (eigene Guards). Aber `cmd/subcmd` ist nicht erfasst — wahrscheinlich fehlerhaft. Empfehlung: nur Pfade die mit `/` (absolut) oder `./`/`../` (relativ zur CWD) starten als "no flag needed" werten; sonstige relative Pfade sind verdächtig. |
| 2.5.19 | `lib/Text/Treesitter/Bash/Security/Rule/MissingAbsolutePath.pm` | 8-12 | ENHANCEMENT | Die KNOWN_COMMANDS-Liste sollte aus dem System-PATH ableitbar sein (optional via Config), aber als Default-Whitelist sinnvoll. |

### 2.6 `Checker.pm` Bugs

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 2.6.1 | `lib/Text/Treesitter/Bash/Security/Checker.pm` | 33-36 | BUG (API inconsistency) | `$rule->check($command)` kann zurueckgeben: nichts (DangerousFlags, SensitiveAccess, EnvDangerousVars, MissingAbsolutePath), einen einzelnen Hashref (DangerousFlags, SensitiveAccess, EnvDangerousVars), oder eine Liste (PathTraversal, UnquotedExpansion). In `Checker::check_commands`: `my @result = $rule->check($command); push @issues, @result if @result;` — bei single Hashref wird der Hashref zwangsweise in einen Key-Value-Pair-Liste flachgedrueckt? Nein, `@result = $hashref` macht eine 1-element-Liste. Aber bei `my @result = ...` und `$result` waere `(key1, value1, key2, value2)` nicht das gewollte Verhalten. **Aber** `$rule->check($command)` ist aufgerufen im **Scalar-Listen-Kontext** (`my @result = $rule->check(...)`). In Listenkontext gibt ein Rule-Sub entweder `()` oder `(hashref,)` oder `(hash1, hash2)` zurueck. Das matched. Aber: was, wenn eine Rule `(hashref)` zurueckgibt (also `(single_hash)`)? OK. Was, wenn `undef` zurueckgibt? `my @result = (undef)` — dann ist `@result = (undef)` und `if @result` ist **wahr** (Anzahl = 1), dann wird `push @issues, undef` was den Issues-Stack korrumpiert. Gluecklicherweise geben die existierenden Regeln `undef` zurueck via `return;` (leere Liste). Trotzdem: kein defensiver Guard. Empfehlung: `push @issues, grep { ref eq 'HASH' } $rule->check($command);` |
| 2.6.2 | `lib/Text/Treesitter/Bash/Security/Checker.pm` | 14-22 | BUG (anti-pattern, perl-core) | `require`-inline-Pattern existiert hier zwar nicht direkt, aber `Module::Load::load($class_name)` ist ein "lazy load" von Klassen, die der User als Strings in `rules => ['PathTraversal', ...]` reingibt. Das ist der einzige Fall, in dem `require`/`load` legitim ist (Klassenname kommt aus Config). Aber: in `check_source` Z. 45 steht `require Text::Treesitter::Bash;` — das ist **nicht** legitim (Klassenname statisch), und genau das perl-core-Anti-Pattern (siehe §3.1). |
| 2.6.3 | `lib/Text/Treesitter/Bash/Security/Checker.pm` | 17-18 | BUG (silently fails) | `load($class_name)` laedt das Modul, aber wenn `load` fehlschlaegt (Klasse existiert nicht), wirft `load` und das bricht den ganzen Audit. Wenn die Rule-Klasse geladen wird aber kein `check` definiert, kommt erst zur Laufzeit der `die`-Call in `Rule::check`. Empfehlung: Validierung bei `new()`: nach `load` pruefen ob `$class_name->can('check')` und sonst `croak` mit klarer Meldung. |

---

## 3. Robustheit / Perl-Idiome (perl-core-Konformitaet)

### 3.1 `require` statt `use`

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 3.1.1 | `lib/Text/Treesitter/Bash/Security/Checker.pm` | 45 | BUG (perl-core) | `require Text::Treesitter::Bash;` innerhalb von `check_source`. Der Klassenname ist statisch und bekannt — perl-core verbietet `require` als "lazy optimization". Empfehlung: oberhalb der Sub `use Text::Treesitter::Bash;` hinzufuegen. Konsequenz: minimal hoehere Startup-Zeit (ein `use` vs `require`), aber konsistent mit der Hausregel. |

### 3.2 Module-Loading

Alle anderen `use`-Statements sind sauber, mit expliziten Import-Listen (`qw(...)`). Pflicht-Variante von perl-core ist eingehalten.

### 3.3 Stil / Whitespace

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 3.3.1 | (alle lib/*.pm) | - | NIT | **2-space-Indent ist sauber durchgehalten** (verifiziert via `cat -A` fuer Bash.pm, Checker.pm, Rule.pm, alle 6 Rule/*.pm und alle t/*.t). Keine Tabs gefunden. perl-core-konform. |
| 3.3.2 | `lib/Text/Treesitter/Bash/Security/Rule/DangerousFlags.pm` | 11 | NIT | Trailing comma: `'--force',` — perl-core sagt: **No trailing commas at the end of multi-line lists**. `--recursive' => ...` ist die letzte Zeile, kein trailing comma. Aber Z. 11 (`--recursive' => ...`) ist die letzte — kein trailing comma. Konform. (Aber `t/10_commands.t` benutzt `=>`-Listen mit trailing commas — egal, perl-core sagt explizit "in multi-line lists".) |
| 3.3.3 | (mehrere) | - | NIT | Einige `=>` Listen enden ohne trailing comma (konsistent). OK. |

### 3.4 `use strict; use warnings;`

Alle .pm-Files und alle t/*.t haben `use strict;` und `use warnings;`. Konform.

### 3.5 Versions

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 3.5.1 | (alle lib/*.pm) | - | NIT | `$VERSION = '0.002';` ist in allen 9 Files konsistent. Perl-core-Konvention: Getty-Distributions haben die **next-unreleased** Version im Repo (CPAN ist 0.001, Repo ist 0.002). `Changes` Z. 1 hat `{{$NEXT}}` als Marker — passt. Konsistent. |
| 3.5.2 | `cpanfile` | 7 | NIT | `requires 'Text::Treesitter', '0.13';` — `Text::Treesitter` ist kein Getty-Modul, also keine perl-core-Pflicht zu pinnen. Aber `Text::Treesitter::Bash` selbst ist nicht required (Self-Reference). OK. |

### 3.6 Moose / OOP

Das Projekt benutzt **kein** Moose/Moo. Plain OO mit `bless` und `use parent`. Das ist legitim fuer ein kleines Dist — perl-core erlaubt explizit Moose-Freiheit. Aber: perl-core erwaehnt Moose-Patterns als Defaults; hier ist die Abwesenheit eine bewusste Wahl, nicht ein Versehen.

### 3.7 Path::Tiny

Korrekt eingesetzt (`path(...)`, `->child(...)`, `->mkpath`, `->copy`, `->parent(...)`). perl-core-konform.

### 3.8 JSON

Wird im Code nicht benutzt (Tree-Sitter-Bindings liefern direkt Perl-Objekte). OK.

### 3.9 Forbidden-Pattern-Check

| Pattern | Vorkommen |
|---|---|
| `require Foo` im Method-Body | `Checker.pm:45` — siehe 3.1.1 |
| 4-space indent | Nicht gefunden (cat -A clean) |
| `File::Spec` in new code | Nicht gefunden |
| `Data::Dumper` | Nicht gefunden |
| `$VERSION` aus Repo in cpanfile | Nicht vorhanden (keine Self-Reference) |

---

## 4. Fehlende Edge-Case-Tests

Die existierenden Tests sind gut strukturiert (10_commands.t mit 11 Sub-Cases, 20_findings.t mit 7 Sub-Cases, 30_security.t mit 7 Sub-Cases). Aber sie decken viele Syntax-Konstrukte nicht ab:

| # | Konstrukt | Beispiel | Erwartung | Test fehlt |
|---|---|---|---|---|
| 4.1 | `\|&` Pipe-Failure | `curl x \|& sh` | network_to_shell-Finding | JA (kritisch, BUG 2.1.1) |
| 4.2 | `time foo` | `time rm -rf /tmp` | Command extrahiert, name='time' | JA |
| 4.3 | `time foo && bar` | - | time-Command mit after_op='&&' | JA |
| 4.4 | `! cmd` Negation | `! rm -rf /tmp` | Inner-Command extrahiert, context=['negated'] | JA |
| 4.5 | `cmd1; cmd2` Semicolon | `ls; pwd` | after_op=';', before_op=';' | nur als Teil von 10_commands.t Z.41 |
| 4.6 | Here-String `cmd <<< $var` | `cat <<< "hello"` | cat extrahiert mit Source inkl. redirect | JA |
| 4.7 | Here-Doc `cmd <<EOF ... EOF` | `cat <<EOF\nfoo\nEOF` | cat extrahiert, body-Text nicht als Command | JA |
| 4.8 | Function-Def `foo() { bar; }` | - | bar extrahiert, ggf. function-name extrahiert | JA |
| 4.9 | Alias `alias ll='ls -la'` | - | alias-Command extrahiert, argv=['alias', "ll='ls -la'"] | JA |
| 4.10 | Arithmetic `$((x+y))` | `echo $((1+2))` | echo extrahiert, kein neuer Command | JA |
| 4.11 | Brace-Expansion `{a,b,c}` | `echo {a,b,c}` | echo extrahiert, argv[1]='{a,b,c}' | JA |
| 4.12 | Array `${arr[@]}` | `cat ${arr[@]}` | cat extrahiert, argv enthaelt ${arr[@]} | JA (BUG 2.3.3) |
| 4.13 | Backticks `` `cmd` `` | `echo \`date\`` | echo extrahiert, date in context=[command_substitution] | JA (in 10_commands.t Z.218) |
| 4.14 | Process-Substitution `<(cmd)` | `diff <(ls a) <(ls b)` | ls a und ls b beide extrahiert | JA |
| 4.15 | Case-Statement | `case $x in a) cmd ;; esac` | cmd extrahiert | JA |
| 4.16 | For-Loop | `for f in *.txt; do cat $f; done` | cat extrahiert, context enthaelt 'for_statement' | JA |
| 4.17 | While-Loop | `while read x; do echo $x; done` | echo extrahiert | JA |
| 4.18 | If/Then/Else | `if cmd; then other; fi` | cmd und other extrahiert | JA |
| 4.19 | Subshell `(cmd1; cmd2)` | `(cd /tmp; ls)` | cd und ls beide extrahiert, subshell-context | JA |
| 4.20 | Grouping `{ cmd1; cmd2; }` | `{ cd /tmp; ls; }` | cd und ls extrahiert | JA |
| 4.21 | Background `cmd &` | `sleep 30 &` | sleep extrahiert mit after_op='&' | JA (BUG 2.2.6) |
| 4.22 | Negation `! cmd` | - | siehe 4.4 | JA |
| 4.23 | Newline-Separator | `cmd1\ncmd2` | newline als after_op | NIT (BUG 2.2.7) |
| 4.24 | Empty Source | `''` | leerer commands-list, leerer findings-list | JA |
| 4.25 | Invalid UTF-8 | `"\xff"` | croak mit klarer Meldung | JA (BUG 2.4.1) |
| 4.26 | Nil-bytes | `"foo\0bar"` | croak oder klare Behandlung | JA |
| 4.27 | Compound-Assignment | `export FOO="hello world"` | argv=['export', 'FOO="hello world"'] oder korrekt getrennt | JA (BUG 2.1.7) |
| 4.28 | Quoted-With-Vars | `echo "safe $foo" $bar/baz` | $bar/baz wird als unquoted-expansion erkannt | JA (BUG 2.5.7) |
| 4.29 | Single-Quoted-With-Dollar | `echo '$foo'` | KEIN unquoted-expansion Finding | JA (BUG 2.5.9) |
| 4.30 | Builtin `cd /tmp` | - | KEIN MissingAbsolutePath Finding | JA (BUG 2.5.16) |

Prioritaet: 4.1 (Sicherheits-BUG), 4.7 (kann Commands in Here-Doc-Body fälschlich matchen), 4.6, 4.21.

---

## 5. Vorschlaege fuer neue Rules

Alle folgen dem Contract aus `.claude/skills/treesitter-bash-security/SKILL.md`.

### 5.1 `DangerousCommands`

Severity: `high` fuer `nc -e`, `mkfs`, `fdisk`, `shutdown`, `reboot`, `systemctl disable <service>`, `iptables -F`, `chmod 777`, `dd of=/dev/sd*`, `curl ... | bash` (redundant zu network_to_shell).

```perl
package Text::Treesitter::Bash::Security::Rule::DangerousCommands;
# ABSTRACT: Detect well-known dangerous commands
our $VERSION = '0.002';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

my @DANGEROUS = (
  [ qr/^nc$/,   qr/-e\b/, 'high',   'nc with -e executes a remote shell on connect' ],
  [ qr/^ncat$/, qr/-e\b/, 'high',   'ncat with -e executes a remote shell' ],
  [ qr/^mkfs/,  undef,    'high',   'mkfs formats a filesystem, destroys data' ],
  [ qr/^fdisk$/,undef,    'high',   'fdisk manipulates partition table' ],
  [ qr/^shutdown$/, undef,'medium', 'shutdown halts the system' ],
  [ qr/^reboot$/,   undef,'medium', 'reboot halts the system' ],
  [ qr/^systemctl$/, qr/^(?:disable\|mask\|stop)\b/, 'high', 'systemctl disables services' ],
  [ qr/^dd$/,       qr{\bof=/dev/(?:sd|hd|nvme|vd|mmcblk)}, 'high', 'dd writing to block device' ],
  [ qr/^chmod$/,    qr/\A0*777\z/, 'high', 'chmod 777 (world-writable)' ],
  [ qr/^chmod$/,    qr/\A0*[2367]77\z/, 'medium', 'chmod granting group/other write' ],
);

sub check {
  my ( $class, $command ) = @_;
  my $name = $command->{command} // q{};
  my $argv = $command->{argv}    // [];
  for my $tuple (@DANGEROUS) {
    my ( $name_re, $arg_re, $severity, $message ) = @$tuple;
    next unless $name =~ $name_re;
    next if $arg_re && !scalar grep { ref $_ ? 0 : $_ =~ $arg_re } @$argv;
    return {
      rule     => 'DangerousCommands',
      severity => $severity,
      message  => $message,
      command  => $name,
      argv     => $argv,
    };
  }
  return;
}

1;
```

### 5.2 `ForkBomb`

Erkennt `:(){ :\|:& };:` und `bash -c ':() { :\|:& }; :'`.

```perl
package Text::Treesitter::Bash::Security::Rule::ForkBomb;
# ABSTRACT: Detect classic bash fork-bomb function definitions
our $VERSION = '0.002';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

sub check {
  my ( $class, $command ) = @_;
  my $source = $command->{source} // q{};
  return unless $source =~ m/:?\(\)\s*\{?\s*:?\|:?\s*&?\s*\}?\s*;?:?/;
  return {
    rule     => 'ForkBomb',
    severity => 'high',
    message  => 'Potential fork-bomb pattern detected',
    source   => $source,
  };
}

1;
```

Besser: AST-basiert (function_definition mit body, der self-recursion + background macht). Aber die Regex-Variante ist ein pragmatischer Start. Siehe follow-up.

### 5.3 `CryptoMining`

Erkennt typische Miner-Downloader und Mining-Pool-URLs.

```perl
package Text::Treesitter::Bash::Security::Rule::CryptoMining;
# ABSTRACT: Detect cryptocurrency miner indicators
our $VERSION = '0.002';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

my @MINER_INDICATORS = (
  [ qr/xmrig|minerd|cgminer|bfgminer|cpuminer/i, 'high',   'Known miner binary name' ],
  [ qr/(?:pool\.|mining\.)?(?:monero|bitcoin|cryptonight|nicehash|miningrigrental)/i, 'medium', 'Mining pool reference' ],
  [ qr/stratum\+tcp:\/\//i, 'medium', 'Stratum mining protocol URL' ],
);

sub check {
  my ( $class, $command ) = @_;
  my $source = $command->{source} // q{};
  for my $tuple (@MINER_INDICATORS) {
    my ( $re, $sev, $msg ) = @$tuple;
    if ( $source =~ $re ) {
      return {
        rule     => 'CryptoMining',
        severity => $sev,
        message  => $msg,
        source   => $source,
        match    => $&,
      };
    }
  }
  return;
}

1;
```

### 5.4 `InsecureDownload`

Erkennt `curl`/`wget` ohne TLS-Verifikation: `--insecure`, `-k`, oder fehlendes `https://` zu HTTP-Endpunkten.

```perl
package Text::Treesitter::Bash::Security::Rule::InsecureDownload;
# ABSTRACT: Detect downloads with disabled/insecure transport
our $VERSION = '0.002';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

my @FETCHERS = qw( curl wget fetch );

sub check {
  my ( $class, $command ) = @_;
  my $name = $command->{command} // q{};
  return unless any { $name eq $_ } @FETCHERS;
  my $argv = $command->{argv} // [];

  if ( scalar grep { $_ eq '-k' || $_ eq '--insecure' || $_ eq '--no-check-certificate' } @$argv ) {
    return {
      rule     => 'InsecureDownload',
      severity => 'high',
      message  => 'TLS verification disabled on download',
      command  => $name,
      argv     => $argv,
    };
  }
  if ( scalar grep { m{^http://} } @$argv ) {
    return {
      rule     => 'InsecureDownload',
      severity => 'medium',
      message  => 'Plaintext HTTP URL used for download',
      command  => $name,
      argv     => $argv,
    };
  }
  return;
}

1;
```

### 5.5 `SensitiveRedirect` (haengt an 2.2.3)

Erkennt `> /etc/passwd`, `>> /etc/shadow`, `> /dev/sda` etc. Benoetigt den Redirects-Hash-Feld (siehe ENHANCEMENT 2.2.3).

### 5.6 `NetworkListener`

Erkennt `nc -l`, `ncat -l`, `socat TCP-LISTEN`, `python -m http.server`, `php -S 0.0.0.0`, `ssh -R` (Reverse-Tunnel), `ssh -D` (SOCKS-Proxy).

```perl
package Text::Treesitter::Bash::Security::Rule::NetworkListener;
# ABSTRACT: Detect commands opening network listeners
our $VERSION = '0.002';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

sub check {
  my ( $class, $command ) = @_;
  my $name = $command->{command} // q{};
  my $argv = $command->{argv}    // [];

  if ( $name eq 'nc' || $name eq 'ncat' ) {
    return { rule => 'NetworkListener', severity => 'high',
             message => 'nc/ncat listener',
             command => $name, argv => $argv }
      if grep { $_ eq '-l' || $_ eq '--listen' } @$argv;
  }
  if ( $name =~ /\Apython/ && grep { $_ eq 'http.server' } @$argv ) {
    return { rule => 'NetworkListener', severity => 'medium',
             message => 'Python HTTP server',
             command => $name, argv => $argv };
  }
  if ( $name eq 'ssh' ) {
    return { rule => 'NetworkListener', severity => 'high',
             message => 'ssh reverse tunnel or SOCKS proxy',
             command => $name, argv => $argv }
      if grep { $_ eq '-R' || $_ eq '-D' } @$argv;
  }
  return;
}

1;
```

### 5.7 `PrivilegeEscalation`

Erkennt `sudo su`, `sudo bash`, `sudo -i`, `su -`, `doas`, `pkexec`, `chmod u+s` (SetUID), `chmod g+s` (SetGID).

---

## 6. Dokumentations-Luecken

### 6.1 POD in lib/*

| # | Datei | Sev | Befund |
|---|-------|-----|--------|
| 6.1.1 | (alle lib/**/*.pm) | ENHANCEMENT | **Jedes File hat nur `# ABSTRACT:` und keinen POD-Block.** Kein `=head1 NAME`, `=head1 SYNOPSIS`, `=head1 DESCRIPTION`, `=head1 METHODS`. CPAN-Index, `perldoc`, IDE-Tooltips sind leer. Empfehlung: per File mindestens NAME + SYNOPSIS + METHOD-Liste. |
| 6.1.2 | `lib/Text/Treesitter/Bash.pm` | ENHANCEMENT | Felder des Command-Hash sind nirgends dokumentiert (nur im treesitter-bash-security Skill). Empfehlung: POD-Section "COMMAND HASH FIELDS" mit Tabelle. |
| 6.1.3 | `lib/Text/Treesitter/Bash/Security/Rule.pm` | ENHANCEMENT | Die Klasse erlaubt 3 Rueckgabe-Formate (undef, single Hashref, Array of Hashrefs). Das ist nirgends dokumentiert. Empfehlung: im POD klar festhalten — der Skill tut es, der Code nicht. |
| 6.1.4 | `lib/Text/Treesitter/Bash/Security/Checker.pm` | ENHANCEMENT | Methoden `check_source` und `check_commands` haben keine POD. Empfehlung: SYNOPSIS mit beiden Aufruf-Pfaden. |

### 6.2 README

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 6.2.1 | `README.md` | 1-29 | ENHANCEMENT | Nur 28 Zeilen. Keine DESCRIPTION-Section, keine "How does it work?"-Section, keine Beispiele ueber das 3-Zeilen-Synopsis hinaus, keine LICENSE-Info, keine "Why?"-Begruendung. Empfehlung: Description, Architecture (kurz), mehrere Examples (Plugin-Rules, Custom-Rule), Limitations, Links zu Tree-sitter-bash und Text::Treesitter. |

### 6.3 SECURITY.md / RULES.md / Cookbook

| # | Datei | Sev | Befund |
|---|-------|-----|--------|
| 6.3.1 | `docs/SECURITY-RESEARCH.md` | ENHANCEMENT | Existiert nicht. Der treesitter-bash-security Skill erwaehnt es: "Update `docs/SECURITY-RESEARCH.md` or write a `docs/RULES.md` mapping rule → threat." Empfehlung: Anlegen. |
| 6.3.2 | `docs/RULES.md` | ENHANCEMENT | Existiert nicht (nur `docs/rules/` Verzeichnis, aber kein Inhalt). Sollte jede Rule dokumentieren: Threat-Model, False-Positive-Rate, Beispiele, Override-Pfad. |
| 6.3.3 | `docs/COOKBOOK.md` | ENHANCEMENT | Existiert nicht. Empfehlung: "Wie schreibe ich eine eigene Rule?", "Wie integriere ich in einen Approval-Flow?", "Wie pinne ich die Tree-sitter-Grammars-Version?". |

### 6.4 Changes

| # | Datei | Zeilen | Sev | Befund |
|---|-------|--------|-----|--------|
| 6.4.1 | `Changes` | 1-11 | NIT | Nur ein Eintrag. Akzeptabel fuer v0.001, aber ab v0.002 wird mehr erwartet. Empfehlung: Beim Bump detailliert listen (welche Rules neu, welche Bugs gefixt, welche API-Aenderungen). |

### 6.5 Beispiele in POD

Keine. Keine einzige `=example`/`=for example`-Section in irgendeinem File.

### 6.6 LICENSE / Contributors

| # | Datei | Sev | Befund |
|---|-------|-----|--------|
| 6.6.1 | top-level `LICENSE` | ENHANCEMENT | Nicht im Repo-Root (das Share-LICENSE wird vom Walker kopiert). `dist.ini` setzt `license = Perl_5`, aber CPAN-User brauchen die Datei im Dist-Archive. Empfehlung: prüfen, ob `[@Author::GETTY]` eine LICENSE-File providet oder manuelles Anlegen noetig ist. |

---

## 7. API-Design-Notes

### 7.1 Inkonsistenz: `commands()` vs. `findings()`

**Beobachtung:**
- `commands()` gibt eine **strukturierte Liste von Hash-Refs** zurueck mit klar definierten Feldern (`source`, `command`, `argv`, `start_byte`, `end_byte`, `context`, `before_op`, `after_op`).
- `findings()` gibt eine **lose Liste von Hash-Refs** zurueck mit unterschiedlichen Feldern pro Finding-Typ:
  - `shell_interpreter` / `dynamic_shell` / `shell_eval`: `{ type, message, command }`
  - `network_to_shell`: `{ type, message, commands => [ $left, $right ] }`
- `Security::Rule::*->check()` gibt ein **drittes Format** zurueck: `{ rule, severity, message, command, argv, source, arg, var, ... }` (felder je Rule anders).

**Konsequenz:** Wer ein Findings-Format konsumieren will, muss drei Formate parsen. Ein Aufrufer kann `findings()` und `check_source()` nicht in dieselbe Liste packen, ohne Konflikte zu loesen (`type` vs `rule`, `commands` vs `argv`).

**Empfehlung:** Vereinheitlichen. Vorschlag:

```perl
# Alle Findings haben:
{
  type     => 'shell_interpreter' | 'network_to_shell' | 'dangerous_flags' | ...,
  rule     => 'DangerousFlags' | 'NetworkToShell' | ...,   # die Klasse die es gefunden hat
  severity => 'low' | 'medium' | 'high',
  message  => 'Human-readable explanation',
  # Context (eines oder mehrere):
  command  => $cmd_basename,
  argv     => \@argv,           # falls relevant
  source   => $source_text,     # falls relevant
  arg      => $matched_arg,     # falls Single-Arg
  commands => [ \@left, \@right ], # falls Paar/Liste
  start_byte => $cmd_start,
  end_byte   => $cmd_end,
}
```

### 7.2 Inkonsistenz: `check_source` vs `check_commands`

- `check_commands(@commands)` erwartet eine **Liste** von Hashes.
- `check_source($source)` erwartet einen **Skalar**.

Beide haben ihre Berechtigung (Caller hat schon geparst vs. nicht), aber: `check_commands` deserialisiert seine `@commands` als Liste (`my @commands`), aber `commands()` returnt auch eine Liste. Das ist OK.

**Issue:** `check_commands` akzeptiert KEINE Hash-Ref-Liste, sondern immer eine flache Liste. Wenn der Caller `my $cmds = [ {...}, {...} ]; $checker->check_commands(@$cmds);` schreibt, geht das. Aber wenn er `$checker->check_commands(\@cmds)` schreibt, geht es schief (der innere Array-Ref wird als ein "command" interpretiert, was eine Method-Call-Warnung produziert).

**Empfehlung:** Alternative Signature `$checker->check_commands(\@cmds)` und `$checker->check_commands(@cmds)` beide akzeptieren, oder dokumentieren dass nur die flache Liste geht.

### 7.3 Sollte `commands()` auch `findings()` liefern koennen?

Aktuell hat `commands()` keine Finding-Logik. Ein Aufrufer muss `findings()` separat aufrufen.

**Frage:** Sollte `commands()` optional `findings` als Feld pro Command liefern? Vorschlag:

```perl
$bash->commands($source, { with_findings => 1 });
# liefert commands mit zusaetzlichem Feld findings => [ {...}, {...} ]
```

**Pro:**
- Ein Aufruf, alle Daten.
- Konsumenten koennen pro-Command Findings aggregieren.

**Con:**
- `commands()` wird zur Policy-Schicht (Security-Checker-Logik).
- Verletzt Separation of Concerns (Parsing vs. Security).
- Mehrfacher Aufruf (gleiches Source, andere Rule-Sets) wuerde Findings redundant berechnen.

**Empfehlung:** Nein, `commands()` bleibt rein. Wenn Bedarf entsteht, einen separaten `audit()`-Endpunkt anbieten, der `commands()` + `Checker` kombiniert.

### 7.4 Sollte `findings()` Rule-pluggable sein?

Aktuell ist `findings()` hartcodiert mit 4 Finding-Typen. Der `Security::Checker` hat einen eigenen Rule-Mechanismus, aber er kann die eingebauten Findings nicht emulieren oder ersetzen.

**Empfehlung:** Den eingebauten `findings()`-Code in Rules verschieben (`ShellInterpreter`, `DynamicShell`, `ShellEval`, `NetworkToShell`), dann hat der User die Wahl: `findings()` = Default-Rule-Set (jetzt hartcodiert), und `Security::Checker` = Custom-Rule-Set. Siehe Befund 2.1.2.

### 7.5 Rule-Return-Konsistenz

Aktuell:
- `DangerousFlags`, `SensitiveAccess`, `EnvDangerousVars`, `MissingAbsolutePath`: return single Hash oder `undef`.
- `PathTraversal`, `UnquotedExpansion`: return Array of Hashes.

**Empfehlung:** **Immer Array.** Selbst single-Hash-Regeln geben `[ $hash ]` zurueck oder `()`. Dann ist `Checker::check_commands` trivial (`push @issues, @{ $rule->check($command) };`) und die API ist konsistent.

### 7.6 Sollte `Checker` `Source` exposen?

Aktuell bekommt jede Rule nur den Command-Hash. Wenn die Rule auf den ganzen Source-Text zugreifen will (fuer Cross-Command-Checks), muss sie via `argv` und `source` rekonstruieren. `EnvDangerousVars` braucht z.B. den Source weil `export LD_PRELOAD=...` nicht im argv steht, sondern am Anfang des Commands.

**Verbesserung:** Der Command-Hash enthaelt bereits `source` (das ist der Source-Text des Command-Subtrees, also nur dieser Command, nicht der ganze Bash-Source). Cross-Command-Checks (wie `network_to_shell`) brauchen aber Zugriff auf die ganze Liste — der macht das aktuell in `Bash::findings` direkt. Wenn das in Rules verschoben wird (siehe 2.1.2), muss der Checker einen zusaetzlichen `audit($source)`-Endpunkt bekommen, der die ganze Liste sieht.

---

## 8. Zusammenfassung — Top-Priority-Fixes

Wenn nur die naechsten 1-2 Tage Zeit sind, hier die hoechste Prioritaet (Reihenfolge = Reihenfolge der Umsetzung):

1. **2.1.1** `|&` in network_to_shell ergaenzen. (5 Minuten, klarer Security-BUG.)
2. **3.1.1** `require Text::Treesitter::Bash;` in `Checker.pm` zu `use` migrieren. (1 Minute, perl-core-Pflicht.)
3. **2.5.1** Dead `%DANGEROUS_FLAGS` entweder nutzen oder loeschen. (5 Minuten.)
4. **2.5.7** `UnquotedExpansion` per-Variable pruefen statt per-Source. (30 Minuten, klare FN-Fix.)
5. **2.5.5** PathTraversal `..` generisch matchen statt `/etc/../`-Praefix. (5 Minuten.)
6. **2.5.16** Shell-Builtins zur MissingAbsolutePath-Whitelist. (15 Minuten.)
7. **2.2.1** Subshell/Process-Substitution `before_op` propagieren. (30 Minuten.)
8. **2.2.6** Background-Operator `&` in `_operator_text`. (5 Minuten.)
9. **2.3.3** `array`, `subscript`, `regex`, `extglob_pattern` zu `_is_argument_node`. (10 Minuten.)
10. **6.1.1** Mindestens NAME + SYNOPSIS + METHODS-POD in jedem File. (1-2 Stunden, haengt an der Writers-Disziplin.)
11. **4.1** Test fuer `curl x |& sh` (gehoert zu Fix #1). (10 Minuten.)
12. **2.1.2** `Bash::findings` in 4 Rule-Klassen aufspalten. (1-2 Stunden, Refactor mit Tests.)

---

*Report-Ende. Stand: 2026-08-15, gegen `33d5e82`.*
