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
| `SensitiveAccess`      | high / medium / low | 26 credential / introspection paths (see [RULES.md](RULES.md)) |
| `EnvDangerousVars`     | high / low | `LD_PRELOAD`, `LD_AUDIT`, `DYLD_*`, `BASH_ENV`, `ENV`, `CDPATH`, `GIT_DIR` |
| `UnquotedExpansion`    | medium | unquoted `$VAR` followed by `/`, `-`, `.` |
| `MissingAbsolutePath`  | low | commands without `/`, `./`, `../`, not in allowlist or shell builtin |
| `DangerousExpansion`   | high | `${!var}`, `${var@P}`, `${var=value}`, `${$(...)}` (CVE-2026-29783 class) |
| `ReverseShellSink`     | high / medium | `nc -e`, `ncat -e`, `socat exec:`, `bash -i` + `/dev/tcp`, `ssh ProxyCommand`, `mkfifo` |
| `DangerousFilesystem`  | high / medium | `dd of=/dev/sdX`, `mkfs*`, `fdisk`, `parted`, `: > /etc/...`, `truncate -s 0`, `shred`, mount/loop/crypto |
| `IFSManipulation`      | high / medium | `IFS=` overrides, `$IFS`-bound expansions |

## Built-in `findings` (in `Text::Treesitter::Bash`)

These run without explicit rule setup:

| Finding | Matches |
|---------|---------|
| `shell_interpreter`  | `sh`, `bash`, `dash`, `zsh`, `fish`, `ksh` invoked directly |
| `dynamic_shell`      | `bash -c …`, `perl -e …`, `ruby -e …`, `python -c …`, `node -e …` |
| `shell_eval`         | `eval`, `source`, `.` |
| `network_to_shell`   | `curl`/`wget`/`fetch`/`aria2c` piped into a shell interpreter |

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
