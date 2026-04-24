package Text::Treesitter::Bash::Security::Rule::PathTraversal;
# ABSTRACT: Detect path traversal patterns in commands

use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

sub check {
  my ( $class, $command ) = @_;

  my @issues;

  for my $arg ( @{ $command->{argv} // [] } ) {
    next if ref $arg;

    if ( $arg =~ m{(?:\.\./|/etc/../|/proc/../|/sys/../)} ) {
      push @issues, {
        rule     => 'PathTraversal',
        severity => 'high',
        message  => "Path traversal detected: $arg",
        arg      => $arg,
        command  => $command->{command}
      };
    }

    if ( $arg =~ m{(?:\A|\s)(/proc/self|/proc/\$\$|/sys/fs)} ) {
      push @issues, {
        rule     => 'PathTraversal',
        severity  => 'medium',
        message   => "Sensitive path access: $arg",
        arg       => $arg,
        command   => $command->{command}
      };
    }
  }

  return @issues;
}

1;