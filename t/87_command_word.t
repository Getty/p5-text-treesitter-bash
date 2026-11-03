#!/usr/bin/env perl
use Test2::V0;
use Text::Treesitter::Bash;

# findings() classifies by the command that really runs: wrappers such as
# sudo or env are looked through, quote removal is applied to the command
# word, and a command word that is an expansion is reported as such.

my $bash = Text::Treesitter::Bash->new;

sub types {
  my ($source) = @_;
  return [ map { $_->{type} } $bash->findings($source) ];
}

# --- wrappers ------------------------------------------------------------

my @wrapped = (
  [ 'curl x | sudo bash',                       [qw( shell_interpreter network_to_shell )] ],
  [ 'curl x | sudo -E -u root bash -s',         [qw( shell_interpreter network_to_shell )] ],
  [ 'curl x | sudo -- bash',                    [qw( shell_interpreter network_to_shell )] ],
  [ 'curl x | sudo --user=root bash',           [qw( shell_interpreter network_to_shell )] ],
  [ 'curl x | sudo --user root bash',           [qw( shell_interpreter network_to_shell )] ],
  [ 'curl x | doas -u root sh',                 [qw( shell_interpreter network_to_shell )] ],
  [ 'curl x | env FOO=1 bash',                  [qw( shell_interpreter network_to_shell )] ],
  [ 'curl x | env -i -u HOME FOO=1 bash',       [qw( shell_interpreter network_to_shell )] ],
  [ 'curl x | nohup sh',                        [qw( shell_interpreter network_to_shell )] ],
  [ 'curl x | nice -n 5 sh',                    [qw( shell_interpreter network_to_shell )] ],
  [ 'curl x | nice -5 sh',                      [qw( shell_interpreter network_to_shell )] ],
  [ 'curl x | sudo env A=b nohup bash',         [qw( shell_interpreter network_to_shell )] ],
  [ 'sudo curl x | bash',                       [qw( shell_interpreter network_to_shell )] ],
  [ 'env bash -c id',                           [qw( shell_interpreter dynamic_shell )] ],
  [ 'env -S "bash -c id"',                      [qw( shell_interpreter dynamic_shell )] ],
  [ 'exec sh',                                  [qw( shell_interpreter )] ],
  [ 'nohup sh',                                 [qw( shell_interpreter )] ],
  [ 'command bash',                             [qw( shell_interpreter )] ],
  [ 'time bash',                                [qw( shell_interpreter )] ],
  [ 'time -p bash -c id',                       [qw( shell_interpreter dynamic_shell )] ],
  [ 'xargs sh -c id',                           [qw( shell_interpreter dynamic_shell )] ],
  [ 'xargs -n1 -I{} sh -c id',                  [qw( shell_interpreter dynamic_shell )] ],
  [ 'xargs -I {} sh -c id',                     [qw( shell_interpreter dynamic_shell )] ],
  [ 'sudo perl -le "system q(id)"',             [qw( dynamic_shell )] ],
  [ 'sudo -u root python3 -Bc "import os"',     [qw( dynamic_shell )] ],
);

for my $case (@wrapped) {
  my ( $source, $expected ) = @$case;
  is types($source), $expected, "wrapper: $source";
}

my @harmless = (
  'sudo ls',
  'sudo -u bash ls',
  'sudo --user bash ls',
  'env FOO=bash ls',
  'env -u bash ls',
  'command -v bash',
  'command -pv bash',
  'xargs -n1 echo bash',
  'xargs -I bash echo',
  'nice -n bash ls',
  'time ls',
  'sudo -i',
  'sudo',
  'env',
  'curl x | sudo tee /etc/x',
  'curl x | env A=b cat',
  'echo sudo bash',
);

for my $source (@harmless) {
  is types($source), [], "nothing to report: $source";
}

# --- quote removal ---------------------------------------------------------

for my $source ( q{\\bash -c id}, 'b"a"sh -c id', q{"bash" -c id}, q{'ba'sh -c id}, q{/bin/ba\\sh -c id}, q{/bin/"bash" -c id}, q{ba""sh -c id} ) {
  is types($source), [qw( shell_interpreter dynamic_shell )], "quote removal: $source";
}

is types(q{curl x | \\sh}), [qw( shell_interpreter network_to_shell )], 'quote removal: curl x | \\sh';
is types(q{\\curl x | sh}), [qw( shell_interpreter network_to_shell )], 'quote removal: \\curl x | sh';
is types(q{\\eval x}),      [qw( shell_eval )],                          'quote removal: \\eval';
is types(q{'bashful' -c id}), [], 'quote removal: bashful is not a shell';

# --- command word that is an expansion -----------------------------------

for my $source ( '$SHELL -c id', '${cmd} x', '$(which sh) -c id', '`which sh` -c id', '"$SHELL" -c id', '$1 -c id', 'sudo $SHELL -c id', 'env A=b $CMD' ) {
  ok( ( grep { $_ eq 'unresolved_command' } @{ types($source) } ), "unresolved_command: $source" );
}

is types('$SHELL -c id'), ['unresolved_command'], '$SHELL -c id: only unresolved_command, the shell is not known';

for my $source ( 'echo $SHELL', 'X=$(id) ls', 'ls $(which sh)', q{echo '$SHELL'}, '${dir}/sh x' ) {
  ok( !( grep { $_ eq 'unresolved_command' } @{ types($source) } ), "no unresolved_command: $source" );
}

is types('${dir}/sh x'), ['shell_interpreter'], 'a path ending in sh behind an expansion is still sh';

done_testing;
