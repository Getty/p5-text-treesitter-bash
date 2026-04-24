package Text::Treesitter::Bash::Security::Rule::DangerousFlags;
# ABSTRACT: Detect dangerous flag combinations in commands
our $VERSION = '0.002';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

my %DANGEROUS_FLAGS = (
  '-r'      => { severity => 'medium', combined => '-rf',   message => 'Recursive delete flag' },
  '-f'      => { severity => 'low',    combined => '-rf',   message => 'Force flag' },
  '--force' => { severity => 'medium', combined => '--force', message => 'Force flag' },
  '--recursive' => { severity => 'medium', combined => '--recursive', message => 'Recursive flag' },
  '-R'      => { severity => 'medium', combined => '-rf',   message => 'Recursive flag' },
);

sub check {
  my ( $class, $command ) = @_;

  my $name = $command->{command} // '';
  my $argv = $command->{argv} // [];

  for my $arg (@$argv) {
    next if ref $arg;

    if ( $arg eq '-rf' ) {
      return {
        rule     => 'DangerousFlags',
        severity => 'high',
        message  => "Dangerous combination: -rf (recursive force delete)",
        command  => $name,
        argv     => $argv
      };
    }

    if ( $arg eq '-r' || $arg eq '-R' || $arg eq '--recursive' ) {
      if ( grep { $_ eq '-f' } @$argv ) {
        return {
          rule     => 'DangerousFlags',
          severity => 'high',
          message  => "Dangerous combination: -rf (recursive force delete)",
          command  => $name,
          argv     => $argv
        };
      }
    }

    if ( $arg eq '--force' ) {
      if ( grep { $_ eq '--recursive' || $_ eq '-r' || $_ eq '-R' } @$argv ) {
        return {
          rule     => 'DangerousFlags',
          severity => 'high',
          message  => "Dangerous combination: --force with recursive flag",
          command  => $name,
          argv     => $argv
        };
      }
    }
  }

  return;
}

1;