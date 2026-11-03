#!/usr/bin/env perl
use Test2::V0;
use Text::Treesitter::Bash;

# Code handed to an interpreter as a string is dynamic_shell, whichever way
# the flag is written: alone, in a cluster of short options, quoted, or
# as a long option.

my $bash = Text::Treesitter::Bash->new;

sub types {
  my ($source) = @_;
  return [ map { $_->{type} } $bash->findings($source) ];
}

my @dynamic = (
  # shells
  'bash -c id',
  'bash -lc id',
  'sh -ec id',
  'bash -xc id',
  'bash -ic id',
  'zsh -fc id',
  'bash -o pipefail -c id',
  q{bash '-lc' id},
  'bash "-c" id',
  '/bin/bash -lc id',
  # perl
  'perl -e 1',
  'perl -le "system q(id)"',
  'perl -we 1',
  'perl -lne print',
  'perl -0777e 1',
  'perl -pi -e 1',
  'perl -Mstrict -e 1',
  'perl -E "say 1"',
  # python
  'python3 -c "import os"',
  'python3 -Bc "import os"',
  'python3 -uc "import os"',
  'python3 -Sc "import os"',
  'python3 -Im http.server',
  'python -m http.server',
  # node
  'node -e 1',
  'node -p 1',
  'node -pe 1',
  'node --print 1',
  'node --eval 1',
  'node --eval=1',
  'node --print=1',
  # ruby
  'ruby -e 1',
  'ruby -ne 1',
  'ruby -pe 1',
  'ruby -rjson x.rb',
);

my @plain = (
  'bash script.sh',
  'bash -x script.sh',
  'bash -l script.sh',
  'bash -o errexit script.sh',
  'bash --norc script.sh',
  'perl script.pl',
  'perl -Mstrict script.pl',
  'perl -I lib script.pl',
  'perl -Ilib script.pl',
  'perl -w script.pl',
  'perl -l script.pl',
  'python3 script.py',
  'python3 -u script.py',
  'python3 -Wignore script.py',
  'python3 -Xdev script.py',
  'python3 -B script.py',
  'node script.js',
  'node --inspect script.js',
  'ruby script.rb',
  'ruby -w script.rb',
  'ruby -W:no-experimental script.rb',
  'echo -c',
  'echo -lc',
  'ls -lc',
);

for my $source (@dynamic) {
  ok( ( grep { $_ eq 'dynamic_shell' } @{ types($source) } ), "dynamic_shell: $source" );
}

for my $source (@plain) {
  ok( !( grep { $_ eq 'dynamic_shell' } @{ types($source) } ), "no dynamic_shell: $source" );
}

# A shell run with -lc is still a shell, and the finding says dynamic.
is types('bash -lc id'), [ 'shell_interpreter', 'dynamic_shell' ], 'bash -lc: shell_interpreter and dynamic_shell';

done_testing;
