package Text::Treesitter::Bash::Security::Rule::EnvDangerousVars;
# ABSTRACT: Detect dangerous environment variables in commands

use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

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