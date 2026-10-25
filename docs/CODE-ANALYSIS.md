# Code analysis: Text::Treesitter::Bash

As of: 2026-08-15
Codebase state: v0.002 (repo, unreleased) / v0.001 (CPAN)
Related skills: `.claude/skills/getty-perl-core/SKILL.md`, `.claude/skills/treesitter-bash-security/SKILL.md`

Findings are numbered and carry a suffix for the severity:

- **BUG** — functionally wrong / security problem / silent data loss
- **ENHANCEMENT** — a sensible extension that makes the behavior clearer / better
- **NIT** — style / docs / micro

All line numbers refer to the current commit (`33d5e82`).

---

## 1. Architecture overview

```
+------------------+       parse() / commands()        +-----------------------+
|  Source text     |---------------------------------->| Text::Treesitter::Bash|
|  (scalar string) |                                   |  lib/.../Bash.pm      |
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
                                                       |  Command list     |
                                                       |  (Array of Hashes)|
                                                       +---+----------+----+
                                                           |          |
                                       check_commands() ---+          +-- (built-in)
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

### Data flow

**Path A (built-in findings):**
```
source --[Bash::findings]--> commands --[findings()]--> List<Finding{type,message,command}>
                                          |
                                          +-- per command: shell_interpreter / dynamic_shell / shell_eval
                                          +-- per pair:       network_to_shell
```

**Path B (plugin rules):**
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

### Assessment

- **Two parallel finding pipelines** with different data formats (see §7).
  Built-in findings (`shell_interpreter`, `dynamic_shell`, `shell_eval`,
  `network_to_shell`) are hardcoded in `Bash.pm`. All other rules
  live as plugin classes in `Security/Rule/`. The dividing line is
  undocumented and causes confusion: why is `network_to_shell`
  built in, but `unquoted_expansion` a plugin?
- **The command hash is well documented** (see treesitter-bash-security skill §"Command
  hash fields"). Rules rely on it.
- **Rule.pm** is a pure ABC class; `Checker.pm` loads plugin classes
  at runtime via `Module::Load::load()`. That is the only place
  where a genuine "runtime plugin load" would be legitimate (getty-perl-core allows
  it for dynamic class names from config / DB). But see §3.1.

---

## 2. Correctness problems

### 2.1 Built-in findings (`Bash.pm`)

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 2.1.1 | `lib/Text/Treesitter/Bash.pm` | 76 | BUG | `network_to_shell` only matches `^\|` — i.e. only the normal pipe. **`|&` (pipe-failure, bash-specific) is NOT detected.** `curl https://x \|& sh` is exactly as dangerous as `curl https://x \| sh`. Recommendation: `( $left->{after_op} // '' ) =~ m/^\|(?:&)?/` or explicitly `|\|`. |
| 2.1.2 | `lib/Text/Treesitter/Bash.pm` | 38-89 | ENHANCEMENT | `findings()` duplicates logic that should really be a rule (`shell_interpreter`, `dynamic_shell`, `shell_eval`, `network_to_shell`). Recommendation: move these four finding types into `Security/Rule/*` and turn `findings()` into a thin wrapper that automatically equips the rule collection with a few default rules. Makes the architecture consistent: one mechanism, one place. |
| 2.1.3 | `lib/Text/Treesitter/Bash.pm` | 72 | BUG | `for my $index ( 1 .. $#commands )` — with empty source `$#commands == -1`; the range `1..-1` is empty in modern Perl (good), but in 5.26..5.34 it was `[1, 0]`. No immediate crash, but fragile. Recommendation: `for my $index ( 1 .. scalar(@commands) - 1 )` or an explicit guard. |
| 2.1.4 | `lib/Text/Treesitter/Bash.pm` | 55-61 | BUG | `_is_dynamic_shell` checks `-c` for Perl/Ruby/Node (correct is `-e`), but: Perl also knows `-E`, `-p`, `-n`, `-i`, `-pe`, `-ne`; Ruby knows `-e`, `-r` (related to require), `-rr`; Python knows `-c` (good) plus `-m` (module execution). `perl -e 'rmtree "/"'` is detected, but `perl -E 'say `rmtree "/"`'` is not. Recommendation: extend the whitelist. |
| 2.1.5 | `lib/Text/Treesitter/Bash.pm` | 375-389 | BUG | `_is_dynamic_shell` matches `python` but **not** `python3.11`, because the regex `\Apython(?:\d+(?:\.\d+)?)?\z` does not accept a `python3.11rc1` suffix (not a real-world issue), but `pypy`, `pypy3`, `jython`, `micropython`, `nushell` (nu) are Python OSVs as well. Recommendation: keep an explicit list instead of regex whitespace. |
| 2.1.6 | `lib/Text/Treesitter/Bash.pm` | 47 | NIT | `_is_shell_interpreter` contains `fish` — good — but `csh`, `tcsh`, `ash`, `busybox sh` are missing. NIT because these are rarely used via `-c`, but `csh -c 'rm -rf /'` is just as dangerous. |
| 2.1.7 | `lib/Text/Treesitter/Bash.pm` | 271-283 | BUG | `_simple_command_entry` blindly splits the source text on whitespace: `export FOO="hello world"` becomes `argv = ['export', 'FOO="hello', 'world"']`. `command` is `export`, argv is broken. Rules that regex `argv` cannot analyze `FOO="hello world"` correctly (see `EnvDangerousVars`, which regexes `source` — good — but every rule that builds on `argv` gets broken tokens for compound assignments). Recommendation: take AST values from the tree instead of a string split, or use the tree-sitter `word` node for each argument. |

### 2.2 Walker (`_walk_node`, `_walk_children`, `_walk_command_children`)

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 2.2.1 | `lib/Text/Treesitter/Bash.pm` | 173-176 | BUG | `subshell`, `process_substitution`, `command_substitution` are passed to `_walk_children` with `initial_before_op = undef`. **The operator BEFORE the subshell is lost.** Example: `cmd1 && (cmd2; cmd3)` — `cmd2` gets `before_op = undef`, although it actually sits after `&&`. Recommendation: pass `initial_before_op` through from the `pending_op` of the outer `_walk_children`. |
| 2.2.2 | `lib/Text/Treesitter/Bash.pm` | 183-186 | NIT | `negated_command` sets context `'negated'`, but the negation `!` itself is not represented anywhere in the command hash. Anyone who wants to detect `! rm -rf /` has to match on the context string, which is fragile. Recommendation: `negated => 1` in the hash. |
| 2.2.3 | `lib/Text/Treesitter/Bash.pm` | 188-194 | BUG | `redirected_statement` only handles `body`. The redirects (`>`, `<`, `>>`, `<<<`, `2>&1`) are lost. Recommendation: attach redirects to the command hash as `redirects => [...]` — rules like `WritingToSystemPath` could then detect `> /etc/passwd`. |
| 2.2.4 | `lib/Text/Treesitter/Bash.pm` | 167-171 | NIT | `declaration_command`, `unset_command`, `test_command` are emitted via `_simple_command_entry`. `test_command` (`[ ... ]`, `[[ ... ]]`) is NOT an executable command — it is a condition evaluation. It does not really belong in a finding list. Recommendation: skip `test_command` or mark it with `context => ['test']` and teach rules to ignore it. |
| 2.2.5 | `lib/Text/Treesitter/Bash.pm` | 220-228 | NIT | `_walk_command_children` filters out `command_name`, but not `variable_assignment` (e.g. `FOO=bar cmd`). This produces empty subtrees. Works by accident (no new command is pushed), but suboptimal. |
| 2.2.6 | `lib/Text/Treesitter/Bash.pm` | 297-308 | BUG | `_operator_text` knows `&& \|\| \| \|& ; \n`. **`&` (background) is missing.** Example: `rm -rf / & sleep 5` — `rm` gets no `after_op='&'`. Recommendation: add `return $text if $text eq '&';`. |
| 2.2.7 | `lib/Text/Treesitter/Bash.pm` | 305 | NIT | `return ';' if $text =~ m/^\s*\n\s*$/;` — this is really a newline operator. It would be clearer to return the literal `'\n'` instead of `';'`, because newlines in lists really act as command separators. Consistency: there are two values for the same thing. |
| 2.2.8 | `lib/Text/Treesitter/Bash.pm` | 156-197 | ENHANCEMENT | No specialized handling for `case_statement`, `for_statement`, `while_statement`, `if_statement`, `function_definition`, `elif_clause`, `else_clause`, `do_group`. They fall through to `_walk_children`. Works (inner commands are extracted), but `context` loses these important markers. Recommendation: dedicated branches that extend `context` (analogous to `'pipeline'`). |
| 2.2.9 | `lib/Text/Treesitter/Bash.pm` | 156-197 | ENHANCEMENT | `function_definition` is not handled specially. The function name `foo` from `foo() { bar; }` is lost. Recommendation: a `function_definition` branch with function name extraction. |

### 2.3 `_command_entry`

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 2.3.1 | `lib/Text/Treesitter/Bash.pm` | 230-265 | BUG (potential) | The `shift @fields` pair pattern assumes that `field_names_with_child_nodes` returns strictly alternating `(field_name, child_node)` pairs. If the binding call returns an odd count, or if the pair structure changes in an update, the mapping gets corrupted: the next `child` comes from the wrong field. Recommendation: iterate explicitly over `$node->field_names` and fetch the child via `$node->child_by_field_name($field)`. Avoids the assumption about the pair structure and is more robust. |
| 2.3.2 | `lib/Text/Treesitter/Bash.pm` | 248-250 | BUG | The unfielded-children logic captures everything that matches `_is_argument_node` AND comes AFTER the name (`$seen_name`). But tree-sitter can also have unnamed `word` children BEFORE the name (e.g. with `env VAR=val cmd` — when `env` comes as an unnamed `word` BEFORE `command_name`). These are then swallowed. Recommendation: use only `argument` field iteration; discard unnamed children entirely or collect them as meta. |
| 2.3.3 | `lib/Text/Treesitter/Bash.pm` | 310-324 | BUG | `_is_argument_node` does not include: `array`, `subscript`, `regex`, `extglob_pattern`. `${arr[@]}` is silently dropped as an argument. Consequence: `cat ${arr[@]}` has `argv = ['cat']` instead of `['cat', '${arr[@]}']`. Rules like `UnquotedExpansion` cannot see it. Recommendation: consult tree-sitter-bash node-types.json and keep a complete list. |
| 2.3.4 | `lib/Text/Treesitter/Bash.pm` | 326-338 | BUG | `_clean_word` strips `"..."` and `'...'` quotes, but: for `'$foo'` (single-quoted, i.e. literal `$foo`), `$foo` is returned. Anyone using `command` as a bare name gets a dollar sign — leads to regex false hits in `KNOWN_COMMANDS` and rule logic. Recommendation: treat quoted words as a separate class (see treesitter-bash-security skill §"argv caveat"). |

### 2.4 Unhandled edge cases

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 2.4.1 | `lib/Text/Treesitter/Bash.pm` | 23-27 | BUG | `parse()` only accepts `defined $source`. The empty string `""` is allowed (good), but: NUL bytes (`"\0"`) in the source probably lead to a tree-sitter-internal error, because tree-sitter is byte-oriented and most grammars reject NUL. Invalid UTF-8 (`"\xff"`) without `utf8::decode` likewise. No validation, no `croak`. Recommendation: at least UTF-8 validation via `utf8::valid($source)` and a clear error. |
| 2.4.2 | `lib/Text/Treesitter/Bash.pm` | 113-139 | NIT | `_build_runtime_lang_dir` extracts 5 files into a `tempdir` with `CLEANUP => 1`. That is OK, but: the `tempdir` path ends up in `$self->{_tmpdir}` and is never used. Dead state. Recommendation: either drop it or expose the path via an accessor (debugging). |
| 2.4.3 | `lib/Text/Treesitter/Bash.pm` | 99-104 | NIT | `Text::Treesitter::Language::build` is called without explicit error handling. On a compile failure, `local *STDOUT = $capture` catches the diagnostics — which only end up in `$stdout` and are never shown. Recommendation: if `! -f $lang_lib` after `build`, still `croak` with `$stdout`, otherwise the build error is invisible. |
| 2.4.4 | `lib/Text/Treesitter/Bash.pm` | 141-154 | NIT | `_find_share_dir` looks at `dist_dir()` first, then `$INC`-based. If both fail, it croaks. But: the `INC` variant uses `parent(4)`, which is magic and breaks on package restructuring. Recommendation: compute a concrete path (`path(__FILE__)->parent(3)->child('share')` like other Getty dists). |

### 2.5 Bugs in the rules

#### DangerousFlags

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 2.5.1 | `lib/Text/Treesitter/Bash/Security/Rule/DangerousFlags.pm` | 8-14 | BUG (dead code) | `%DANGEROUS_FLAGS` is defined but **never read**. The actual logic lives in the `if` chains below. Recommendation: either use `%DANGEROUS_FLAGS` as a lookup table (DRY) or delete it. |
| 2.5.2 | `lib/Text/Treesitter/Bash/Security/Rule/DangerousFlags.pm` | 22-58 | BUG | Only `rm` / `mv` / `cp` make sense with `-rf`. But the rule fires for **every** command. `gcc -f foo` would be triggered as an `-rf` variant if `-r` were present. The `next if ref $arg` logic does check, but the rule does not know the command — `ls -rf` would also be reported as "dangerous combination: -rf". Recommendation: a whitelist of commands for which `-rf`/`-fr`/`--force` with `--recursive` is actually destructive (rm, mv, cp, find -delete, chmod -R ...). |
| 2.5.3 | `lib/Text/Treesitter/Bash/Security/Rule/DangerousFlags.pm` | 35-44 | BUG | The rule checks for `-r \|\| -R \|\| --recursive`, but `rm -fr` (reversed order) is **not** detected: arguments are checked in argv order, and with `-fr` `$arg` equals `-fr`, which matches the first `if` branch — ok, that matches. But `rm -fR` (capital R) matches neither `-r` nor `-R` (the if chain distinguishes upper and lower case). Recommendation: case-insensitive regex `qr/-[rR]\|--(?:recursive\|force)/`. |
| 2.5.4 | `lib/Text/Treesitter/Bash/Security/Rule/DangerousFlags.pm` | 35 | BUG | `-R` as a capital letter matches, but `-RF` (combined) or `-FR` does not, because `$arg` must be exactly equal. Recommendation: parse combined arguments. |

#### PathTraversal

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 2.5.5 | `lib/Text/Treesitter/Bash/Security/Rule/PathTraversal.pm` | 16 | BUG | The regex `(?:\.\./\|/etc/../\|/proc/../\|/sys/../)` catches `../` only at the start of **a path segment** that must have a hardcoded `/etc/../` directly before it. `cat /etc/foo/../shadow` (the real traversal form, because after `foo/..` it goes back to `etc`) is **NOT** matched. Recommendation: `\.\.(?:/\|$)` is enough — every `..` is suspicious, not just the hardcoded prefixes. |
| 2.5.6 | `lib/Text/Treesitter/Bash/Security/Rule/PathTraversal.pm` | 26 | BUG | `(?:\A\|\s)(/proc/self\|/proc/\$\$\|/sys/fs)` — `\A` matches at the start of the string. For `cat /proc/self/maps` there is `cat ` in front (space). The anchor `\A\|\s` does not apply before `cat `, because `\A` is at the start and `\s` counts after `cat `. So the match must be directly after whitespace or at the start. That works for `/proc/self/...` as its own arg, but `cat "-flag" /proc/self` matches because of the whitespace before it. Confusing: two separate branches with the same problem, needlessly duplicated. Recommendation: unify. |

#### UnquotedExpansion

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 2.5.7 | `lib/Text/Treesitter/Bash/Security/Rule/UnquotedExpansion.pm` | 14 | BUG (false negative) | `$source !~ m{".*\$[a-zA-Z_]}` excludes the whole source from the check as soon as **any** double-quoted variable value exists. Example: `echo "safe $foo" $bar/baz` — the negative match sees `"safe $foo"` and matches; the rule skips EVERYTHING, so `$bar/baz` (the dangerous one) is not reported. Recommendation: check per variable, not per source. |
| 2.5.8 | `lib/Text/Treesitter/Bash/Security/Rule/UnquotedExpansion.pm` | 14 | BUG (false negative) | A double-quoted string with variables WITHOUT a slash after them is not detected either. But that is OK here because it is not the goal. However: `${var}` and `$((...))` are not matched (`$` followed by `(`, `(`, or `{`). Recommendation: extend the pattern. |
| 2.5.9 | `lib/Text/Treesitter/Bash/Security/Rule/UnquotedExpansion.pm` | 14 | BUG (false positive) | Single-quoted strings like `echo '$foo'` contain `$foo`, but single quotes do NOT expand. The rule still reports it as a risk because it finds `$foo` as bare. Recommendation: check the single-quote context in the source, or go to the tree-sitter AST (see treesitter-bash-security skill §"Don't use ref to detect quoted strings"). |
| 2.5.10 | `lib/Text/Treesitter/Bash/Security/Rule/UnquotedExpansion.pm` | 22 | NIT | `substr($source, $pos + length($var), 1)` looks at only 1 character after the variable name. If that is `} ` (`${var}`), it does not hit. But `$var}` as a bare name does not match the regex `\$[a-zA-Z_][a-zA-Z0-9_]*` at all. Edge case. |
| 2.5.11 | `lib/Text/Treesitter/Bash/Security/Rule/UnquotedExpansion.pm` | 23 | NIT | `m{[/\-\.]}` — a dot also triggers, which makes sense for `echo "$var.txt"` (word splitting via IFS). But with `echo "$var."` (argument with a trailing dot) it is often intended. A threshold question. |

#### EnvDangerousVars

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 2.5.12 | `lib/Text/Treesitter/Bash/Security/Rule/EnvDangerousVars.pm` | 27 | BUG (false positive) | `\b(?:export\s+)?\Q$var\E\b` — the `export` prefix is optional, so it also matches `MY_LD_PRELOAD_TEST=foo`. Thanks to `\b` (word boundary) this only applies when the last character of `$var` (e.g. `D` in `LD_PRELOAD`) is not followed by a word character. But `MY_LD_PRELOAD` ends in `D`, the `_` before it is a word char — `\b` in between does not match. So OK. But: `LD_PRELOAD_X` would not match, because `_` is a word character. Correct. Edge case passes. |
| 2.5.13 | `lib/Text/Treesitter/Bash/Security/Rule/EnvDangerousVars.pm` | 8-17 | ENHANCEMENT | The list is small. Missing: `PYTHONPATH` (arbitrary code injection via `python`), `NODE_PATH` (likewise), `PERL5LIB` / `PERL5OPT` (Perl prepend and `-M` flag), `RUBYLIB` / `RUBYOPT`, `IFS` (word splitting), `PS4` (debug source trigger in `set -x`), `PROMPT_COMMAND`, `SHELLOPTS`, `BASH_FUNC_*` (exportable bash functions since Bash 4.0). |

#### SensitiveAccess

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 2.5.14 | `lib/Text/Treesitter/Bash/Security/Rule/SensitiveAccess.pm` | 8-19 | BUG (false positive) | `/dev/` matches `/dev/null`, `/dev/zero` etc. — which are used extremely often (`echo > /dev/null`, `dd if=/dev/zero`). Severity is `low`, so not critical, but `/dev/null` as "Device file access" with low severity is misleading. Recommendation: whitelist `/dev/null`, `/dev/zero`, `/dev/std{in,out,err}`, `/dev/urandom`, `/dev/random`, `/dev/tty`. |
| 2.5.15 | `lib/Text/Treesitter/Bash/Security/Rule/SensitiveAccess.pm` | 8-19 | ENHANCEMENT | The patterns are very Unix-centric. Missing: macOS Keychain, Windows paths, container-relevant (`/var/run/docker.sock`), kernel modules (`/lib/modules/`), browser profiles (`~/.config/google-chrome/`), GnuPG (`~/.gnupg/`), `~/.netrc`, `~/.pgpass`. |

#### MissingAbsolutePath

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 2.5.16 | `lib/Text/Treesitter/Bash/Security/Rule/MissingAbsolutePath.pm` | 8-12 | BUG (false positive) | `%KNOWN_COMMANDS` is maintained by hand. Missing: **shell builtins** (`cd`, `pwd`, `echo`, `printf`, `read`, `test`, `[`, `[[`, `exit`, `return`, `set`, `unset`, `declare`, `typeset`, `local`, `export`, `eval`, `exec`, `source`, `.`, `alias`, `unalias`, `hash`, `type`, `command`, `builtin`, `shift`, `getopts`, `trap`, `wait`, `jobs`, `fg`, `bg`, `kill`, `logout`, `times`, `ulimit`, `umask`, `help`, `history`, `pushd`, `popd`, `dirs`, `shopt`, `complete`, `compgen`, `mapfile`, `readarray`). Every call of a builtin without an absolute path is reported as a false positive. Recommendation: add a shell builtin whitelist. |
| 2.5.17 | `lib/Text/Treesitter/Bash/Security/Rule/MissingAbsolutePath.pm` | 27-34 | BUG | If the name does not start with `[a-zA-Z_]` (e.g. `1foo`, `(foo)`, `[foo]`), a finding is generated — but these are often syntactic constructs, not commands. Recommendation: `return` without a finding for names that do not match `^[a-zA-Z_][a-zA-Z0-9_+\-.]*$`. |
| 2.5.18 | `lib/Text/Treesitter/Bash/Security/Rule/MissingAbsolutePath.pm` | 19-21 | NIT | `return if $name =~ m{/}` — a command with a slash but not absolute (`./script.sh`, `../bin/cmd`, `subdir/cmd`) is skipped. OK for `./` and `../` (their own guards). But `cmd/subcmd` is not covered — probably wrong. Recommendation: treat only paths starting with `/` (absolute) or `./`/`../` (relative to the CWD) as "no flag needed"; other relative paths are suspicious. |
| 2.5.19 | `lib/Text/Treesitter/Bash/Security/Rule/MissingAbsolutePath.pm` | 8-12 | ENHANCEMENT | The KNOWN_COMMANDS list should be derivable from the system PATH (optionally via config), but makes sense as a default whitelist. |

### 2.6 `Checker.pm` Bugs

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 2.6.1 | `lib/Text/Treesitter/Bash/Security/Checker.pm` | 33-36 | BUG (API inconsistency) | `$rule->check($command)` can return: nothing (DangerousFlags, SensitiveAccess, EnvDangerousVars, MissingAbsolutePath), a single hashref (DangerousFlags, SensitiveAccess, EnvDangerousVars), or a list (PathTraversal, UnquotedExpansion). In `Checker::check_commands`: `my @result = $rule->check($command); push @issues, @result if @result;` — is a single hashref forcibly flattened into a key-value pair list? No, `@result = $hashref` makes a 1-element list. But with `my @result = ...` and `$result`, `(key1, value1, key2, value2)` would not be the intended behavior. **However**, `$rule->check($command)` is called in **list context** (`my @result = $rule->check(...)`). In list context a rule sub returns either `()` or `(hashref,)` or `(hash1, hash2)`. That matches. But: what if a rule returns `(hashref)` (i.e. `(single_hash)`)? OK. What if it returns `undef`? `my @result = (undef)` — then `@result = (undef)` and `if @result` is **true** (count = 1), so `push @issues, undef` corrupts the issue stack. Fortunately the existing rules return the empty list via `return;`, not `undef`. Still: no defensive guard. Recommendation: `push @issues, grep { ref eq 'HASH' } $rule->check($command);` |
| 2.6.2 | `lib/Text/Treesitter/Bash/Security/Checker.pm` | 14-22 | BUG (anti-pattern, getty-perl-core) | The inline `require` pattern does not exist directly here, but `Module::Load::load($class_name)` is a "lazy load" of classes the user passes as strings in `rules => ['PathTraversal', ...]`. That is the only case in which `require`/`load` is legitimate (the class name comes from config). But: `check_source` line 45 has `require Text::Treesitter::Bash;` — that is **not** legitimate (static class name), and exactly the getty-perl-core anti-pattern (see §3.1). |
| 2.6.3 | `lib/Text/Treesitter/Bash/Security/Checker.pm` | 17-18 | BUG (silently fails) | `load($class_name)` loads the module, but if `load` fails (the class does not exist), `load` throws and that aborts the whole audit. If the rule class loads but defines no `check`, the `die` call in `Rule::check` only comes at runtime. Recommendation: validate in `new()`: after `load`, check whether `$class_name->can('check')` and otherwise `croak` with a clear message. |

---

## 3. Robustness / Perl idioms (getty-perl-core conformance)

### 3.1 `require` instead of `use`

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 3.1.1 | `lib/Text/Treesitter/Bash/Security/Checker.pm` | 45 | BUG (getty-perl-core) | `require Text::Treesitter::Bash;` inside `check_source`. The class name is static and known — getty-perl-core forbids `require` as a "lazy optimization". Recommendation: add `use Text::Treesitter::Bash;` above the sub. Consequence: minimally higher startup time (one `use` vs `require`), but consistent with the house rule. |

### 3.2 Module loading

All other `use` statements are clean, with explicit import lists (`qw(...)`). The mandatory getty-perl-core variant is followed.

### 3.3 Style / whitespace

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 3.3.1 | (all lib/*.pm) | - | NIT | **2-space indent is consistently kept** (verified via `cat -A` for Bash.pm, Checker.pm, Rule.pm, all 6 Rule/*.pm and all t/*.t). No tabs found. getty-perl-core conformant. |
| 3.3.2 | `lib/Text/Treesitter/Bash/Security/Rule/DangerousFlags.pm` | 11 | NIT | Trailing comma: `'--force',` — getty-perl-core says: **No trailing commas at the end of multi-line lists**. `--recursive' => ...` is the last line, no trailing comma. But line 11 (`--recursive' => ...`) is the last one — no trailing comma. Conformant. (But `t/10_commands.t` uses `=>` lists with trailing commas — doesn't matter, getty-perl-core explicitly says "in multi-line lists".) |
| 3.3.3 | (several) | - | NIT | Some `=>` lists end without a trailing comma (consistent). OK. |

### 3.4 `use strict; use warnings;`

All .pm files and all t/*.t have `use strict;` and `use warnings;`. Conformant.

### 3.5 Versions

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 3.5.1 | (all lib/*.pm) | - | NIT | `$VERSION = '0.002';` is consistent in all 9 files. Perl core convention: Getty distributions have the **next unreleased** version in the repo (CPAN is 0.001, repo is 0.002). `Changes` line 1 has `{{$NEXT}}` as marker — fits. Consistent. |
| 3.5.2 | `cpanfile` | 7 | NIT | `requires 'Text::Treesitter', '0.13';` — `Text::Treesitter` is not a Getty module, so no getty-perl-core obligation to pin it. And `Text::Treesitter::Bash` itself is not required (self-reference). OK. |

### 3.6 Moose / OOP

The project uses **no** Moose/Moo. Plain OO with `bless` and `use parent`. That is legitimate for a small dist — getty-perl-core explicitly allows going without Moose. But: getty-perl-core mentions Moose patterns as defaults; here the absence is a deliberate choice, not an oversight.

### 3.7 Path::Tiny

Used correctly (`path(...)`, `->child(...)`, `->mkpath`, `->copy`, `->parent(...)`). getty-perl-core conformant.

### 3.8 JSON

Not used in the code (the tree-sitter bindings return Perl objects directly). OK.

### 3.9 Forbidden pattern check

| Pattern | Occurrences |
|---|---|
| `require Foo` in a method body | `Checker.pm:45` — see 3.1.1 |
| 4-space indent | Not found (cat -A clean) |
| `File::Spec` in new code | Not found |
| `Data::Dumper` | Not found |
| `$VERSION` from the repo in cpanfile | Not present (no self-reference) |

---

## 4. Missing edge case tests

The existing tests are well structured (10_commands.t with 11 sub-cases, 20_findings.t with 7 sub-cases, 30_security.t with 7 sub-cases). But they do not cover many syntax constructs:

| # | Construct | Example | Expectation | Test missing |
|---|---|---|---|---|
| 4.1 | `\|&` pipe-failure | `curl x \|& sh` | network_to_shell finding | YES (critical, BUG 2.1.1) |
| 4.2 | `time foo` | `time rm -rf /tmp` | command extracted, name='time' | YES |
| 4.3 | `time foo && bar` | - | time command with after_op='&&' | YES |
| 4.4 | `! cmd` negation | `! rm -rf /tmp` | inner command extracted, context=['negated'] | YES |
| 4.5 | `cmd1; cmd2` semicolon | `ls; pwd` | after_op=';', before_op=';' | only as part of 10_commands.t line 41 |
| 4.6 | Here-string `cmd <<< $var` | `cat <<< "hello"` | cat extracted with source incl. redirect | YES |
| 4.7 | Here-doc `cmd <<EOF ... EOF` | `cat <<EOF\nfoo\nEOF` | cat extracted, body text not as a command | YES |
| 4.8 | Function def `foo() { bar; }` | - | bar extracted, possibly function name extracted | YES |
| 4.9 | Alias `alias ll='ls -la'` | - | alias command extracted, argv=['alias', "ll='ls -la'"] | YES |
| 4.10 | Arithmetic `$((x+y))` | `echo $((1+2))` | echo extracted, no new command | YES |
| 4.11 | Brace expansion `{a,b,c}` | `echo {a,b,c}` | echo extracted, argv[1]='{a,b,c}' | YES |
| 4.12 | Array `${arr[@]}` | `cat ${arr[@]}` | cat extracted, argv contains ${arr[@]} | YES (BUG 2.3.3) |
| 4.13 | Backticks `` `cmd` `` | `echo \`date\`` | echo extracted, date in context=[command_substitution] | YES (in 10_commands.t line 218) |
| 4.14 | Process substitution `<(cmd)` | `diff <(ls a) <(ls b)` | ls a and ls b both extracted | YES |
| 4.15 | Case statement | `case $x in a) cmd ;; esac` | cmd extracted | YES |
| 4.16 | For loop | `for f in *.txt; do cat $f; done` | cat extracted, context contains 'for_statement' | YES |
| 4.17 | While loop | `while read x; do echo $x; done` | echo extracted | YES |
| 4.18 | If/then/else | `if cmd; then other; fi` | cmd and other extracted | YES |
| 4.19 | Subshell `(cmd1; cmd2)` | `(cd /tmp; ls)` | cd and ls both extracted, subshell context | YES |
| 4.20 | Grouping `{ cmd1; cmd2; }` | `{ cd /tmp; ls; }` | cd and ls extracted | YES |
| 4.21 | Background `cmd &` | `sleep 30 &` | sleep extracted with after_op='&' | YES (BUG 2.2.6) |
| 4.22 | Negation `! cmd` | - | see 4.4 | YES |
| 4.23 | Newline separator | `cmd1\ncmd2` | newline as after_op | NIT (BUG 2.2.7) |
| 4.24 | Empty source | `''` | empty commands list, empty findings list | YES |
| 4.25 | Invalid UTF-8 | `"\xff"` | croak with a clear message | YES (BUG 2.4.1) |
| 4.26 | NUL bytes | `"foo\0bar"` | croak or clear handling | YES |
| 4.27 | Compound assignment | `export FOO="hello world"` | argv=['export', 'FOO="hello world"'] or split correctly | YES (BUG 2.1.7) |
| 4.28 | Quoted with vars | `echo "safe $foo" $bar/baz` | $bar/baz is detected as unquoted expansion | YES (BUG 2.5.7) |
| 4.29 | Single-quoted with dollar | `echo '$foo'` | NO unquoted-expansion finding | YES (BUG 2.5.9) |
| 4.30 | Builtin `cd /tmp` | - | NO MissingAbsolutePath finding | YES (BUG 2.5.16) |

Priority: 4.1 (security BUG), 4.7 (can wrongly match commands in a here-doc body), 4.6, 4.21.

---

## 5. Proposals for new rules

All follow the contract from `.claude/skills/treesitter-bash-security/SKILL.md`.

### 5.1 `DangerousCommands`

Severity: `high` for `nc -e`, `mkfs`, `fdisk`, `shutdown`, `reboot`, `systemctl disable <service>`, `iptables -F`, `chmod 777`, `dd of=/dev/sd*`, `curl ... | bash` (redundant with network_to_shell).

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

Detects `:(){ :\|:& };:` and `bash -c ':() { :\|:& }; :'`.

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

Better: AST-based (function_definition with a body that does self-recursion + background). But the regex variant is a pragmatic start. See follow-up.

### 5.3 `CryptoMining`

Detects typical miner downloaders and mining pool URLs.

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

Detects `curl`/`wget` without TLS verification: `--insecure`, `-k`, or a missing `https://` to HTTP endpoints.

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

### 5.5 `SensitiveRedirect` (depends on 2.2.3)

Detects `> /etc/passwd`, `>> /etc/shadow`, `> /dev/sda` etc. Needs the redirects hash field (see ENHANCEMENT 2.2.3).

### 5.6 `NetworkListener`

Detects `nc -l`, `ncat -l`, `socat TCP-LISTEN`, `python -m http.server`, `php -S 0.0.0.0`, `ssh -R` (reverse tunnel), `ssh -D` (SOCKS proxy).

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

Detects `sudo su`, `sudo bash`, `sudo -i`, `su -`, `doas`, `pkexec`, `chmod u+s` (SetUID), `chmod g+s` (SetGID).

---

## 6. Documentation gaps

### 6.1 POD in lib/*

| # | File | Sev | Finding |
|---|-------|-----|--------|
| 6.1.1 | (all lib/**/*.pm) | ENHANCEMENT | **Every file has only `# ABSTRACT:` and no POD block.** No `=head1 NAME`, `=head1 SYNOPSIS`, `=head1 DESCRIPTION`, `=head1 METHODS`. The CPAN index, `perldoc` and IDE tooltips are empty. Recommendation: at least NAME + SYNOPSIS + method list per file. |
| 6.1.2 | `lib/Text/Treesitter/Bash.pm` | ENHANCEMENT | The command hash fields are not documented anywhere (only in the treesitter-bash-security skill). Recommendation: a POD section "COMMAND HASH FIELDS" with a table. |
| 6.1.3 | `lib/Text/Treesitter/Bash/Security/Rule.pm` | ENHANCEMENT | The class allows 3 return formats (undef, single hashref, array of hashrefs). This is not documented anywhere. Recommendation: state it clearly in the POD — the skill does, the code does not. |
| 6.1.4 | `lib/Text/Treesitter/Bash/Security/Checker.pm` | ENHANCEMENT | The methods `check_source` and `check_commands` have no POD. Recommendation: a SYNOPSIS with both call paths. |

### 6.2 README

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 6.2.1 | `README.md` | 1-29 | ENHANCEMENT | Only 28 lines. No DESCRIPTION section, no "How does it work?" section, no examples beyond the 3-line synopsis, no LICENSE info, no "Why?" rationale. Recommendation: description, architecture (short), several examples (plugin rules, custom rule), limitations, links to tree-sitter-bash and Text::Treesitter. |

### 6.3 SECURITY.md / RULES.md / Cookbook

| # | File | Sev | Finding |
|---|-------|-----|--------|
| 6.3.1 | `docs/SECURITY-RESEARCH.md` | ENHANCEMENT | Does not exist. The treesitter-bash-security skill mentions it: "Update `docs/SECURITY-RESEARCH.md` or write a `docs/RULES.md` mapping rule → threat." Recommendation: create it. |
| 6.3.2 | `docs/RULES.md` | ENHANCEMENT | Does not exist (only a `docs/rules/` directory, but no content). It should document every rule: threat model, false positive rate, examples, override path. |
| 6.3.3 | `docs/COOKBOOK.md` | ENHANCEMENT | Does not exist. Recommendation: "How do I write my own rule?", "How do I integrate it into an approval flow?", "How do I pin the tree-sitter grammar version?". |

### 6.4 Changes

| # | File | Lines | Sev | Finding |
|---|-------|--------|-----|--------|
| 6.4.1 | `Changes` | 1-11 | NIT | Only one entry. Acceptable for v0.001, but from v0.002 on more is expected. Recommendation: list in detail at the bump (which rules are new, which bugs fixed, which API changes). |

### 6.5 Examples in POD

None. Not a single `=example`/`=for example` section in any file.

### 6.6 LICENSE / Contributors

| # | File | Sev | Finding |
|---|-------|-----|--------|
| 6.6.1 | top-level `LICENSE` | ENHANCEMENT | Not in the repo root (the share LICENSE is copied by the walker). `dist.ini` sets `license = Perl_5`, but CPAN users need the file in the dist archive. Recommendation: check whether `[@Author::GETTY]` provides a LICENSE file or whether creating one by hand is needed. |

---

## 7. API design notes

### 7.1 Inconsistency: `commands()` vs. `findings()`

**Observation:**
- `commands()` returns a **structured list of hashrefs** with clearly defined fields (`source`, `command`, `argv`, `start_byte`, `end_byte`, `context`, `before_op`, `after_op`).
- `findings()` returns a **loose list of hashrefs** with different fields per finding type:
  - `shell_interpreter` / `dynamic_shell` / `shell_eval`: `{ type, message, command }`
  - `network_to_shell`: `{ type, message, commands => [ $left, $right ] }`
- `Security::Rule::*->check()` returns a **third format**: `{ rule, severity, message, command, argv, source, arg, var, ... }` (fields differ per rule).

**Consequence:** anyone who wants to consume a findings format has to parse three formats. A caller cannot put `findings()` and `check_source()` into the same list without resolving conflicts (`type` vs `rule`, `commands` vs `argv`).

**Recommendation:** unify. Proposal:

```perl
# All findings have:
{
  type     => 'shell_interpreter' | 'network_to_shell' | 'dangerous_flags' | ...,
  rule     => 'DangerousFlags' | 'NetworkToShell' | ...,   # the class that found it
  severity => 'low' | 'medium' | 'high',
  message  => 'Human-readable explanation',
  # Context (one or more):
  command  => $cmd_basename,
  argv     => \@argv,           # if relevant
  source   => $source_text,     # if relevant
  arg      => $matched_arg,     # if single arg
  commands => [ \@left, \@right ], # if pair/list
  start_byte => $cmd_start,
  end_byte   => $cmd_end,
}
```

### 7.2 Inconsistency: `check_source` vs `check_commands`

- `check_commands(@commands)` expects a **list** of hashes.
- `check_source($source)` expects a **scalar**.

Both have their justification (the caller has already parsed vs. not), but: `check_commands` takes its `@commands` as a list (`my @commands`), and `commands()` also returns a list. That is OK.

**Issue:** `check_commands` does NOT accept a hashref list, always a flat list. If the caller writes `my $cmds = [ {...}, {...} ]; $checker->check_commands(@$cmds);`, that works. But if they write `$checker->check_commands(\@cmds)`, it goes wrong (the inner array ref is interpreted as one "command", which produces a method call warning).

**Recommendation:** accept both signatures `$checker->check_commands(\@cmds)` and `$checker->check_commands(@cmds)`, or document that only the flat list works.

### 7.3 Should `commands()` also be able to return `findings()`?

Currently `commands()` has no finding logic. A caller has to call `findings()` separately.

**Question:** should `commands()` optionally return `findings` as a field per command? Proposal:

```perl
$bash->commands($source, { with_findings => 1 });
# returns commands with an additional field findings => [ {...}, {...} ]
```

**Pro:**
- One call, all data.
- Consumers can aggregate findings per command.

**Con:**
- `commands()` becomes the policy layer (security checker logic).
- Violates separation of concerns (parsing vs. security).
- Repeated calls (same source, different rule sets) would compute findings redundantly.

**Recommendation:** no, `commands()` stays pure. If the need arises, offer a separate `audit()` endpoint that combines `commands()` + `Checker`.

### 7.4 Should `findings()` be rule-pluggable?

Currently `findings()` is hardcoded with 4 finding types. `Security::Checker` has its own rule mechanism, but it cannot emulate or replace the built-in findings.

**Recommendation:** move the built-in `findings()` code into rules (`ShellInterpreter`, `DynamicShell`, `ShellEval`, `NetworkToShell`); then the user has the choice: `findings()` = default rule set (hardcoded now), and `Security::Checker` = custom rule set. See finding 2.1.2.

### 7.5 Rule return consistency

Currently:
- `DangerousFlags`, `SensitiveAccess`, `EnvDangerousVars`, `MissingAbsolutePath`: return a single hash or `undef`.
- `PathTraversal`, `UnquotedExpansion`: return an array of hashes.

**Recommendation:** **always an array.** Even single-hash rules return `[ $hash ]` or `()`. Then `Checker::check_commands` is trivial (`push @issues, @{ $rule->check($command) };`) and the API is consistent.

### 7.6 Should `Checker` expose `Source`?

Currently each rule only gets the command hash. If a rule wants to access the whole source text (for cross-command checks), it has to reconstruct it via `argv` and `source`. `EnvDangerousVars`, for example, needs the source because `export LD_PRELOAD=...` is not in argv but at the start of the command.

**Improvement:** the command hash already contains `source` (the source text of the command subtree, i.e. only this command, not the whole bash source). Cross-command checks (like `network_to_shell`) need access to the whole list, though — that is currently done directly in `Bash::findings`. If this moves into rules (see 2.1.2), the checker needs an additional `audit($source)` endpoint that sees the whole list.

---

## 8. Summary — top-priority fixes

If there are only the next 1-2 days, here is the highest priority (order = order of implementation):

1. **2.1.1** Add `|&` to network_to_shell. (5 minutes, clear security BUG.)
2. **3.1.1** Migrate `require Text::Treesitter::Bash;` in `Checker.pm` to `use`. (1 minute, getty-perl-core obligation.)
3. **2.5.1** Either use or delete the dead `%DANGEROUS_FLAGS`. (5 minutes.)
4. **2.5.7** Check `UnquotedExpansion` per variable instead of per source. (30 minutes, clear FN fix.)
5. **2.5.5** Match PathTraversal `..` generically instead of the `/etc/../` prefix. (5 minutes.)
6. **2.5.16** Add shell builtins to the MissingAbsolutePath whitelist. (15 minutes.)
7. **2.2.1** Propagate subshell/process substitution `before_op`. (30 minutes.)
8. **2.2.6** Background operator `&` in `_operator_text`. (5 minutes.)
9. **2.3.3** Add `array`, `subscript`, `regex`, `extglob_pattern` to `_is_argument_node`. (10 minutes.)
10. **6.1.1** At least NAME + SYNOPSIS + METHODS POD in every file. (1-2 hours, depends on the writers' discipline.)
11. **4.1** Test for `curl x |& sh` (belongs to fix #1). (10 minutes.)
12. **2.1.2** Split `Bash::findings` into 4 rule classes. (1-2 hours, refactor with tests.)

---

*End of report. As of: 2026-08-15, against `33d5e82`.*
