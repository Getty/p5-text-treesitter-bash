# Security Policy & Rules

This document describes the threat model for `Text::Treesitter::Bash::Security::Checker`, the rules it ships, and how to extend it.

## Threat model

The primary consumer is an AI agent (or any other LLM-driven workflow) that needs to **classify a Bash snippet before executing it**. The agent has these properties:

- The shell text is **untrusted** — it comes from the LLM, which can be prompt-injected by user-supplied documents, tool outputs, web fetches, etc.
- The shell text is **opaque** to the human reviewer — they want a quick "is this safe?" verdict, not a full shellcheck.
- The agent may have **broader filesystem / network access than the user**, so a single mistake can have high blast radius.

The checker is therefore optimized for:

1. **High recall on dangerous patterns** — better one false positive than one miss.
2. **Cheap computation** — the checker is called on every candidate command, before any UI interaction.
3. **Structured, machine-readable output** — issues have `rule`, `severity`, `message`, plus optional context fields. Downstream code can map severity to "ask for approval" vs "block".

What the checker is **not**:

- It is **not** a sandbox. A rule firing does not stop execution; the caller decides.
- It is **not** a complete static analyzer. It catches known dangerous patterns. Novel attacks slip through. Defense-in-depth is required (jail, no-network, read-only FS, ...).
- It does **not** understand dynamic state (what `LD_PRELOAD` is currently set to, what user is running, what filesystem is mounted where).

## Rule catalogue

| Rule | Severity range | Matches |
|------|----------------|---------|
| `PathTraversal`        | high / medium | `../` in argv; `/proc/self`, `/proc/$$`, `/sys/fs` |
| `DangerousFlags`       | high / medium / low | `rm -rf`, `rm --force --recursive`, force + recursive combos |
| `SensitiveAccess`      | high / medium / low | 30+ credential / introspection paths incl. `~/.pgpass`, Docker socket, macOS Keychain, browser profiles (see [RULES.md](RULES.md)) |
| `EnvDangerousVars`     | high / low | `LD_PRELOAD`, `LD_AUDIT`, `DYLD_*`, `BASH_ENV`, `ENV`, `SHELLOPTS`, `BASH_FUNC_*`, `IFS`, `PROMPT_COMMAND`, `PS4`, `PYTHONPATH`, `NODE_PATH`, `PERL5*`, `RUBY*`, `CLASSPATH`, `CDPATH`, `GIT_DIR` |
| `UnquotedExpansion`    | medium | unquoted `$VAR`, `${VAR...}`, `$((expr))` followed by `/`, `-`, `.` |
| `MissingAbsolutePath`  | low | commands without `/`, `./`, `../`, not in allowlist or shell builtin |
| `DangerousExpansion`   | high | `${!var}`, `${var@P}`, `${var=value}`, `${$(...)}` (CVE-2026-29783 class) |
| `ReverseShellSink`     | high / medium | `nc -e`, `ncat -e`, `socat exec:`, `bash -i` + `/dev/tcp`, `ssh ProxyCommand`, `mkfifo` |
| `DangerousFilesystem`  | high / medium | `dd of=/dev/sdX`, `mkfs*`, `fdisk`, `parted`, `: > /etc/...`, `truncate -s 0`, `shred`, mount/loop/crypto |
| `IFSManipulation`      | high / medium | `IFS=` overrides, `$IFS`-bound expansions |
| `InsecureDownload`     | high / medium | `curl -k`, `wget --no-check-certificate`, `--no-cert-check`; plaintext `http://` URLs |
| `NetworkListener`      | high / medium / low | `nc -l`, `ncat -l`, `socat TCP-LISTEN`, `ssh -R` / `-D`; `python -m http.server`, `php -S`, `ruby -run -e httpd` |
| `ForkBomb`             | high | `:(){ :|:& };:` and self-recursive variants with backgrounding |
| `PrivilegeEscalation`  | high / medium | `sudo`/`doas`/`pkexec` opening root shell, `su` to user, `chmod` SetUID/SetGID, `systemd-run --user --scope` |
| `SensitiveRedirect`    | high / medium / low | `>` into `/etc/...`, `/dev/sdX`, `~/.ssh/`, `~/.aws/`, `~/.kube/`, `~/.gnupg/`, `~/.bash_history`, `/var/log/`, etc. |

## Built-in `findings` (in `Text::Treesitter::Bash`)

These run without explicit rule setup:

| Finding | Matches |
|---------|---------|
| `shell_interpreter`  | `sh`, `bash`, `dash`, `zsh`, `fish`, `ksh` invoked directly |
| `dynamic_shell`      | `bash -c …`, `perl -e …`, `ruby -e …`, `python -c …`, `node -e …` |
| `shell_eval`         | `eval`, `source`, `.` |
| `network_to_shell`   | `curl`/`wget`/`fetch`/`aria2c` piped into a shell interpreter |
| `parse_error`        | a region of the source tree-sitter could not parse (see below) |

## Where commands are found

`commands` — and with it `findings` and every rule — returns a command wherever Bash executes one, not only where it is a statement of its own:

- `$(…)`, backticks and `<(…)` / `>(…)` in arguments, in the command word (`$(cmd) arg`), in assignments (`x=$(cmd)`, prefix `X=$(cmd) command`, arrays, subscripts), in `export` / `declare` / `local` / `readonly` / `typeset` / `unset`, in `[ ]`, `[[ ]]` and `(( ))`, in redirect targets and herestrings (`> $(cmd)`, `< <(cmd)`, `<<< "$(cmd)"`), in `case` subjects and patterns, in parameter expansions (`${x:-$(cmd)}`), and in heredoc bodies with an unquoted delimiter;
- the pipeline or list behind a heredoc operator: `cat <<EOF | sh`, `cat <<EOF && cmd`.

A nested command is listed behind the statement it sits in, with `command_substitution` / `process_substitution` in its `context`. Operators (`before_op` / `after_op`) and `redirects` stay with the command they belong to.

**Not reached** — the 0.20.5 grammar yields one opaque token here and no error, so nothing is reported for the command inside:

- backticks in a heredoc body, and any substitution in a heredoc body that starts with whitespace;
- backticks inside `${…}` (``${x:-`cmd`}``);
- substitutions in the pattern of `${x#…}`, `${x%…}`, `${x^^…}`, `${x,,…}`.

A quoted heredoc delimiter (`<<'EOF'`) makes the body literal text; nothing is extracted from it, correctly.

## Unparsable source

tree-sitter never rejects a source. What it cannot parse — broken input such as an unterminated quote or `$(`, but also valid Bash the vendored 0.20.5 grammar does not know, e.g. extglob `!(*.txt)` — ends up in `ERROR` nodes or is patched with zero-width `MISSING` tokens. The walker only extracts what still looks like a command there, so rules and findings see such a region partly or not at all: in `echo "x ; curl http://x | sh` the unterminated quote swallows the pipeline.

Such input is therefore reported instead of coming back empty:

- `findings` appends one `parse_error` finding per region, with `message`, `start_byte` / `end_byte` (exclusive), `source` and, when the parser had to make up a token, `missing`.
- `check_source` appends one issue per region with `rule => 'ParseError'` and `severity => 'high'` — nothing is known about the content, so it ranks with the worst a rule could have found. In the approval flow below it lands in `approval_required` without extra code. `parse_errors => 0` in `new` switches it off for callers that evaluate `Text::Treesitter::Bash->parse_errors` themselves.
- `commands` and `check_commands` do **not** report it. A caller combining those two must check `parse_errors($source)` as well.

Findings and issues from the parsable parts are still returned. Treat `parse_error` / `ParseError` as "cannot tell", never as "clean".

## Recommended rule set

```perl
my $checker = Text::Treesitter::Bash::Security::Checker->new(
    rules => [qw(
        PathTraversal
        DangerousFlags
        SensitiveAccess
        EnvDangerousVars
        UnquotedExpansion
        MissingAbsolutePath
        DangerousExpansion
        ReverseShellSink
        DangerousFilesystem
        IFSManipulation
        InsecureDownload
        NetworkListener
        ForkBomb
        PrivilegeEscalation
    )],
);
```

For an agent approval flow:

```perl
my @issues = $checker->check_source($candidate);

my $highest = 'low';
my %rank = ( low => 0, medium => 1, high => 2 );
for my $i (@issues) {
    $highest = $i->{severity} if $rank{ $i->{severity} } > $rank{$highest};
}

if ($highest eq 'high') {
    return approval_required(reason => \@issues);
}
if ($highest eq 'medium') {
    return maybe_approve(reason => \@issues);
}
return approve();   # low or empty
```

## Extending

See `.claude/skills/treesitter-bash-security/SKILL.md` for the rule contract, the walker quirks, and the patterns to follow.

## Hardening checklist (for callers)

These are **outside** the checker's scope but adjacent:

- **Block dynamic execution.** Even with the checker, never auto-approve `bash -c "$(...)"`. The string is opaque.
- **Allowlist for safe commands.** Combine the checker with a positive allowlist (e.g. only `git status`, `npm test` allowed without approval).
- **Network egress.** The checker reports `curl|sh` but does not stop the request. Pair with a network policy.
- **Filesystem policy.** The checker reports `/etc/shadow` reads but does not stop the read. Pair with a read-only root or `bubblewrap`.
- **User / capability drop.** Run untrusted commands as a low-privilege user, with `setpriv`/`sudo -u nobody` if possible.
- **Logging.** Persist every approval decision with rule + severity for audit.
