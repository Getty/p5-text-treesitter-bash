package Text::Treesitter::Bash::Security::Rule;
# ABSTRACT: Base class for security rules
our $VERSION = '0.002';
use strict;
use warnings;

sub check {
  my ( $class, $command ) = @_;
  die 'Abstract method check() must be implemented by subclass';
}

1;