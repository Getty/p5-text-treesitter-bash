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

is finding_types('git status && git add . && git commit -m "message"'),
  [],
  'git checkpoint workflow has no security findings';

is finding_types('git checkout HEAD -- .'),
  [],
  'git revert has no security findings';

is finding_types('npm install && npm run build'),
  [],
  'npm chain has no security findings';

is finding_types('pytest && coverage report'),
  [],
  'pytest chain has no security findings';

# --- 2.1.1: `|&` is a pipe, `||` is OR ----------------------------------

is finding_types('curl https://x.invalid/a.sh |& sh'),
  [ 'shell_interpreter', 'network_to_shell' ],
  'pipefail |& into shell is reported as network_to_shell';

is finding_types('curl https://x.invalid/a.sh || echo fallback'),
  [],
  '|| is OR, NOT a pipe — must not trigger network_to_shell';

# --- 2.1.4 / 2.1.5: dynamic-shell flag coverage -------------------------

is finding_types('perl -E \'say "hi"\''),
  [ 'dynamic_shell' ],
  'perl -E (with features) triggers dynamic_shell';

is finding_types('perl -pi -e \'s/foo/bar/\''),
  [ 'dynamic_shell' ],
  'perl -pe triggers dynamic_shell';

is finding_types('perl -ne \'print\''),
  [ 'dynamic_shell' ],
  'perl -ne triggers dynamic_shell';

is finding_types('ruby -rnet/http -e \'puts "x"\''),
  [ 'dynamic_shell' ],
  'ruby -r (require) with -e triggers dynamic_shell';

is finding_types('node -p \'1+1\''),
  [ 'dynamic_shell' ],
  'node -p triggers dynamic_shell';

is finding_types('python3 -m http.server'),
  [ 'dynamic_shell' ],
  'python3 -m triggers dynamic_shell';

is finding_types('python3.11 -c \'print(1)\''),
  [ 'dynamic_shell' ],
  'python3.11 -c triggers dynamic_shell';

is finding_types('pypy -c \'print(1)\''),
  [ 'dynamic_shell' ],
  'pypy -c triggers dynamic_shell';

is finding_types('micropython -c \'print(1)\''),
  [ 'dynamic_shell' ],
  'micropython -c triggers dynamic_shell';

is finding_types('node --eval \'console.log(1)\''),
  [ 'dynamic_shell' ],
  'node --eval triggers dynamic_shell';

# --- 2.1.6: more shell interpreters -------------------------------------

is finding_types('csh -c \'id\''),
  [ 'shell_interpreter', 'dynamic_shell' ],
  'csh -c is recognised';

is finding_types('tcsh -c \'id\''),
  [ 'shell_interpreter', 'dynamic_shell' ],
  'tcsh -c is recognised';

is finding_types('ash -c \'id\''),
  [ 'shell_interpreter', 'dynamic_shell' ],
  'ash -c is recognised';

is finding_types('busybox sh -c \'id\''),
  [ 'shell_interpreter', 'dynamic_shell' ],
  'busybox is recognised as shell interpreter';

done_testing;
