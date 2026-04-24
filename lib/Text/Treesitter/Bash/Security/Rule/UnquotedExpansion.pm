package Text::Treesitter::Bash::Security::Rule::UnquotedExpansion;
# ABSTRACT: Detect unquoted variable expansions that could split

use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

sub check {
  my ( $class, $command ) = @_;

  my @issues;
  my $source = $command->{source} // '';

  if ( $source =~ m{\$[a-zA-Z_][a-zA-Z0-9_]*} && $source !~ m{".*\$[a-zA-Z_]} ) {
    my @unquoted_vars;
    while ( $source =~ m{(\$[a-zA-Z_][a-zA-Z0-9_]*)}g ) {
      push @unquoted_vars, $1;
    }

    for my $var (@unquoted_vars) {
      my $pos = index( $source, $var );
      my $after = substr( $source, $pos + length($var), 1 );
      if ( defined $after && $after =~ m{[/\-\.]} ) {
        push @issues, {
          rule     => 'UnquotedExpansion',
          severity => 'medium',
          message  => "Unquoted variable expansion may cause word splitting: $var",
          var      => $var,
          command  => $command->{command}
        };
      }
    }
  }

  return @issues;
}

1;