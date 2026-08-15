package Text::Treesitter::Bash::Security::Rule::EnvDangerousVars;
# ABSTRACT: Detect dangerous environment variables in commands
our $VERSION = '0.003';
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
  [ 'LD_PRELOAD',   'high',   'LD_PRELOAD can inject shared libraries' ],
  [ 'LD_AUDIT',     'high',   'LD_AUDIT can inject shared libraries' ],
  [ 'DYLD_INSERT_LIBRARIES', 'high', 'macOS DYLD injection' ],
  [ 'DYLD_LIBRARY_PATH',     'high', 'macOS DYLD library path hijacking' ],
  [ 'BASH_ENV',     'high',   'BASH_ENV executes code in non-interactive bash' ],
  [ 'ENV',          'high',   'ENV executes code in interactive bash' ],
  [ 'CDPATH',       'low',    'CDPATH can cause unexpected directory changes' ],
  [ 'GIT_DIR',      'low',    'GIT_DIR can redirect git operations' ],
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