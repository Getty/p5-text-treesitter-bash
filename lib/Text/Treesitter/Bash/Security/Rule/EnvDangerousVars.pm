package Text::Treesitter::Bash::Security::Rule::EnvDangerousVars;
# ABSTRACT: Detect dangerous environment variables in commands
our $VERSION = '0.004';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::EnvDangerousVars - detect dangerous environment variables

=head1 DESCRIPTION

Scans the raw source text of each command for assignments / uses of
environment variables known to enable code execution or hijack
process behaviour:

=over 4

=item high   - C<LD_PRELOAD>, C<LD_AUDIT>, C<DYLD_INSERT_LIBRARIES>, C<DYLD_LIBRARY_PATH>, C<BASH_ENV>, C<ENV>

=item low    - C<CDPATH>, C<GIT_DIR>

=back

Operates on raw source, so false positives are possible when a
variable name appears in an unrelated context (e.g. inside a string).

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>.

=cut

my @DANGEROUS_VARS = (
  # high — direct code execution / library hijacking
  [ 'LD_PRELOAD',            'high', 'LD_PRELOAD can inject shared libraries' ],
  [ 'LD_AUDIT',              'high', 'LD_AUDIT can inject shared libraries' ],
  [ 'DYLD_INSERT_LIBRARIES', 'high', 'macOS DYLD injection' ],
  [ 'DYLD_LIBRARY_PATH',     'high', 'macOS DYLD library path hijacking' ],
  [ 'BASH_ENV',              'high', 'BASH_ENV executes code in non-interactive bash' ],
  [ 'ENV',                   'high', 'ENV executes code in interactive bash' ],
  [ 'SHELLOPTS',             'high', 'SHELLOPTS can change shell error behaviour' ],
  [ 'BASH_FUNC_',            'high', 'BASH_FUNC_* exports shell functions into other bash' ],
  [ 'IFS',                   'high', 'IFS manipulation can change word-splitting' ],
  [ 'PROMPT_COMMAND',        'high', 'PROMPT_COMMAND runs before each prompt' ],
  [ 'PS4',                   'high', 'PS4 with set -x triggers command expansion' ],
  # high — interpreter preload / module injection
  [ 'PYTHONPATH',            'high', 'PYTHONPATH can inject Python modules' ],
  [ 'PYTHONSTARTUP',         'high', 'PYTHONSTARTUP executes Python on interactive start' ],
  [ 'NODE_PATH',             'high', 'NODE_PATH can hijack Node module resolution' ],
  [ 'NODE_OPTIONS',          'high', 'NODE_OPTIONS can inject Node CLI flags' ],
  [ 'PERL5LIB',              'high', 'PERL5LIB can inject Perl modules' ],
  [ 'PERL5OPT',              'high', 'PERL5OPT can inject Perl CLI flags' ],
  [ 'RUBYLIB',               'high', 'RUBYLIB can inject Ruby libraries' ],
  [ 'RUBYOPT',               'high', 'RUBYOPT can inject Ruby CLI flags' ],
  [ 'CLASSPATH',             'high', 'CLASSPATH can inject Java classes' ],
  [ 'LD_LIBRARY_PATH',       'high', 'LD_LIBRARY_PATH overrides library search' ],
  # low — directory / config redirection
  [ 'CDPATH',                'low',  'CDPATH can cause unexpected directory changes' ],
  [ 'GIT_DIR',               'low',  'GIT_DIR can redirect git operations' ],
  [ 'GIT_WORK_TREE',         'low',  'GIT_WORK_TREE can redirect git operations' ],
  [ 'GIT_INDEX_FILE',        'low',  'GIT_INDEX_FILE can redirect git index' ],
);

sub check {
  my ( $class, $command ) = @_;

  my $source = $command->{source} // '';

  for my $tuple (@DANGEROUS_VARS) {
    my ( $var, $severity, $message ) = @$tuple;

    if ( $source =~ m{\b(?:export\s+)?\Q$var\E\b}s ) {
      return {
        rule     => 'EnvDangerousVars',
        severity => $severity,
        message  => "$message in command",
        command  => $command->{command},
        source   => $source
      };
    }
  }

  return;
}

1;