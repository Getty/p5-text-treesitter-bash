package Text::Treesitter::Bash::Security::Rule::MissingAbsolutePath;
# ABSTRACT: Detect commands without absolute paths

use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

my %KNOWN_COMMANDS = map { $_ => 1 } qw(
  ls cat rm cp mv mkdir rmdir chmod chown find grep sed awk
  tar zip unzip curl wget ssh scp git docker kubectl helm
  perl python ruby node npm pip cargo go
);

sub check {
  my ( $class, $command ) = @_;

  my $name = $command->{command} // '';

  return if $name =~ m{/};

  return if $name =~ m{^\./} || $name =~ m{^\.\./};

  return if exists $KNOWN_COMMANDS{$name};

  my $source = $command->{source} // '';

  if ( $name !~ m{^[a-zA-Z_]} ) {
    return {
      rule     => 'MissingAbsolutePath',
      severity => 'low',
      message  => "Command '$name' used without absolute path",
      command  => $name
    };
  }

  return;
}

1;