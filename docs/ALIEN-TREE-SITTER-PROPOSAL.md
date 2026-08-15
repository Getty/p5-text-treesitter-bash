# Proposal: Alien::Tree::Sitter

## Problem

`Text::Treesitter::Bash` (and any other Perl `Text::Treesitter::*` distribution) needs the C library `libtree-sitter` at install/build time. The Perl binding (`Text::Treesitter` 0.13) links against it and links against grammar parsers (e.g. `tree-sitter-bash`) that include `tree_sitter/parser.h` or `tree_sitter/api.h`.

Today:
- Debian stable ships `libtree-sitter-dev 0.22.6`, but its headers were unified (`api.h` only) — the vendored `tree-sitter-bash 0.20.5` includes the removed `parser.h`. So the build fails even with the system package.
- `cpanm Text::Treesitter::Bash` on a vanilla system fails with `tree-sitter unavailable in pkg-config`.
- A consumer needs either root + apt + a manual header shim, or a working tree-sitter 0.20.x (not packaged on Debian stable).

This breaks the "just `cpanm` it" promise that CPAN distributions rely on.

## Solution: Alien::Tree::Sitter

A small CPAN distribution that **vendors a known-good tree-sitter version** and exposes it via the standard Perl-Alien interface (`Alien::Base`). Any Perl distribution that needs tree-sitter declares `Alien::Tree::Sitter` as a build-time dep and gets the headers + library + pkg-config metadata automatically — no system package, no apt, no sudo.

This is the canonical Getty/CPAN solution for native dependencies. Same pattern as `Alien::libxml2`, `Alien::zstd`, `Alien::proj`, etc.

### Distribution layout

```
Alien-Tree-Sitter/
├── cpanfile
├── dist.ini                              [@Author::GETTY]
├── Makefile.PL                           Alien::Base-driven
├── alienfile                             source / list / gather / build
├── src/                                  vendored tree-sitter 0.20.x or 0.22.x
│   ├── lib/include/tree_sitter/api.h     (or parser.h, depending on version)
│   └── lib/src/lib.c
├── share/                                share_dir layout for Alien::Base
└── t/
    └── 00_compile.t                      ensures headers compile
```

### What it provides

- `Alien::Tree::Sitter->install_type` is one of `share` (default — vendored, no system call) or `system` (use system lib if present, otherwise fall back to vendored).
- `Alien::Tree::Sitter->cflags` — `-I/path/to/share/include`
- `Alien::Tree::Sitter->libs`   — `-L/path/to/share/lib -ltree-sitter`
- `Alien::Tree::Sitter->pkg_config` — emits a synthesised `.pc` file with `Name: tree-sitter`, `Version: $VERSION`, `Cflags:`, `Libs:`.
- `Alien::Tree::Sitter->new` (Alien::Base compat) — for older consumers.

### Why vendor rather than download at install time

- No network requirement at install time → reproducible installs.
- Pins a specific ABI version known to work with the vendored grammar.
- Avoids races with upstream ABI changes.

### Which tree-sitter version to vendor

Two options:

| Option | Pros | Cons |
|--------|------|------|
| **0.20.7** (last 0.20.x) | Vendored tree-sitter-bash 0.20.5 builds directly. No shim needed. | Older, no recent fixes. |
| **0.22.6** (Debian stable) | Matches system package, modern API. | Vendored tree-sitter-bash needs upgrade OR a `parser.h` shim that includes `api.h`. |

**Recommendation: vendor 0.22.6**, and provide a one-line `parser.h` shim (in the share dir, NOT in the upstream grammar) so the vendored tree-sitter-bash 0.20.5 builds. Then the `Alien::Tree::Sitter` share dir becomes:

```
share/include/tree_sitter/
├── api.h         (vendored)
└── parser.h      (shim: #include "api.h")
```

This way:

1. Newer grammars (`tree-sitter-bash` 0.21+) work because they include `api.h`.
2. Older grammars (`tree-sitter-bash` 0.20.x) work because of the shim.
3. No vendored-grammar upgrade needed.

### Effect on Text::Treesitter::Bash

Update `cpanfile`:

```perl
on build => sub {
    requires 'Alien::Tree::Sitter';
};
on test => sub {
    requires 'Test2::V0';
};
```

Update `lib/Text/Treesitter/Bash.pm`:

```perl
use Alien::Tree::Sitter;

sub _treesitter {
  ...
  my $cflags = Alien::Tree::Sitter->cflags;
  my $libs   = Alien::Tree::Sitter->libs;
  # pass cflags/libs into Text::Treesitter::Language::build
  ...
}
```

`Text::Treesitter::Language::build` currently does its own gcc invocation. We may need a tiny adapter to inject cflags/libs.

### Workload estimate

| Step | LoC | Time |
|------|-----|------|
| Alien::Tree::Sitter dist skeleton (cpanfile, dist.ini, Makefile.PL, alienfile) | ~100 | 1h |
| Vendor tree-sitter 0.22.6 sources into `src/` | tarball extraction | 30min |
| Write `parser.h` shim | 2 | 5min |
| Add cflags/libs adapter to `Text::Treesitter::Bash` | ~30 | 1h |
| cpanfile update | 5 | 5min |
| Tests for Alien::Tree::Sitter | ~50 | 1h |
| Update `Text::Treesitter::Bash` build path | ~20 | 30min |
| Verify `dzil test` on clean perlbrew | shell | 30min |

Roughly half a day of focused work, mostly mechanical.

### Out of scope (future work)

- `Alien::Tree::Sitter::Grammar::Bash` — bundles `tree-sitter-bash` itself, for consumers that don't want to ship grammar sources.
- Pre-built `.so` binaries per platform (would speed up install at the cost of a release pipeline).

### Open questions

- Vendor tree-sitter as a git submodule of the alienfile, or as a tarball with a checksum? Tarball with checksum is more reproducible.
- Do we want a `share/probe.h` that lets consumers detect what they got (system vs vendored)? Useful for debugging.
