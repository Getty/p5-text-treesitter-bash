package Text::Treesitter::Bash::Security::Rule;
# ABSTRACT: Base class for security rules

use strict;
use warnings;

sub check {
  my ( $class, $command ) = @_;
  die 'Abstract method check() must be implemented by subclass';
}

1;