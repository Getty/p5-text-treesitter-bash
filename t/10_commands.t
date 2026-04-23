use Test2::V0;
use Text::Treesitter::Bash;

my $bash = Text::Treesitter::Bash->new;

sub command_summary {
  my ( $source ) = @_;
  return [
    map {
      +{
        command   => $_->{command},
        argv      => $_->{argv},
        before_op => $_->{before_op},
        after_op  => $_->{after_op},
        context   => $_->{context}
      }
    } $bash->commands($source)
  ];
}

is command_summary('echo a && rm -rf /tmp/x || true; curl example.com | sh'),
  [
    {
      command   => 'echo',
      argv      => [ 'echo', 'a' ],
      before_op => undef,
      after_op  => '&&',
      context   => []
    },
    {
      command   => 'rm',
      argv      => [ 'rm', '-rf', '/tmp/x' ],
      before_op => '&&',
      after_op  => '||',
      context   => []
    },
    {
      command   => 'true',
      argv      => ['true'],
      before_op => '||',
      after_op  => ';',
      context   => []
    },
    {
      command   => 'curl',
      argv      => [ 'curl', 'example.com' ],
      before_op => ';',
      after_op  => '|',
      context   => ['pipeline']
    },
    {
      command   => 'sh',
      argv      => ['sh'],
      before_op => '|',
      after_op  => undef,
      context   => ['pipeline']
    }
  ],
  'commands split across lists and pipelines with operator context';

is command_summary('echo $(id)'),
  [
    {
      command   => 'echo',
      argv      => [ 'echo', '$(id)' ],
      before_op => undef,
      after_op  => undef,
      context   => []
    },
    {
      command   => 'id',
      argv      => ['id'],
      before_op => undef,
      after_op  => undef,
      context   => ['command_substitution']
    }
  ],
  'command substitutions are extracted as nested execution units';

done_testing;
