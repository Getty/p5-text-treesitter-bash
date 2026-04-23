use Test2::V0;
use Text::Treesitter::Bash;

my $bash = Text::Treesitter::Bash->new;

sub finding_types {
  my ( $source ) = @_;
  return [ map { $_->{type} } $bash->findings($source) ];
}

is finding_types('curl https://example.invalid/install.sh | sh'),
  [ 'shell_interpreter', 'network_to_shell' ],
  'network output piped into sh is reported';

is finding_types('bash -c "id"'),
  [ 'shell_interpreter', 'dynamic_shell' ],
  'bash -c is reported as dynamic shell execution';

is finding_types('echo safe'),
  [],
  'plain echo has no findings';

done_testing;
