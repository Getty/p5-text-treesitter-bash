package Text::Treesitter::Bash::Security::Rule::EnvDangerousVars;
# ABSTRACT: Detect dangerous environment variables in commands
our $VERSION = '0.005';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::EnvDangerousVars - detect dangerous environment variables

=head1 DESCRIPTION

Scans the words of each command for assignments (C<NAME=value>,
C<export NAME=value>, C<env NAME=value cmd>) of environment variables
known to enable code execution or hijack process behaviour:

=over 4

=item high   - C<LD_PRELOAD>, C<LD_AUDIT>, C<DYLD_INSERT_LIBRARIES>, C<DYLD_LIBRARY_PATH>, C<BASH_ENV>, C<ENV>

=item low    - C<CDPATH>, C<GIT_DIR>

=back

Only the command's own text is looked at (see
L<Text::Treesitter::Bash::Security::Rule/mask_source>): a name that is
merely mentioned (C<echo ENV>, C<grep IFS file>, C</etc/ENV.conf>, inside
a string, C<$LD_PRELOAD> read) does not fire, and a command nested in
C<$(...)> is reported once, for itself. Any word of the shape
C<NAME=value> counts, whichever command it is an argument of.

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

  # Only the command's own words, with quoted text kept in one piece and
  # nested substitutions, comments and heredoc bodies left out.
  my ($words) = $class->mask_source($source);

  # A variable is set by a word that begins with `NAME=` (or `NAME+=`):
  # at the start of the command or after whitespace or an operator,
  # optionally inside the opening quote of the word (`env "NAME=x"`).
  my $head = qr{ (?: \A | (?<= [\s;&|(] ) ) ["']? }x;

  for my $tuple (@DANGEROUS_VARS) {
    my ( $var, $severity, $message ) = @$tuple;

    # A trailing `_` marks a prefix (BASH_FUNC_): the real variable is
    # the prefix plus an identifier, and it may end in `%%` (an exported
    # function) instead of being assigned.
    my $rx = $var =~ m/_\z/
      ? qr{ $head \Q$var\E [a-zA-Z0-9_]+ (?: %% | \+?= | (?![a-zA-Z0-9_]) ) }x
      : qr{ $head \Q$var\E \+?= }x;

    if ( $words =~ $rx ) {
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