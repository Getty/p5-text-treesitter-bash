package Text::Treesitter::Bash::Security::Rule::UnquotedExpansion;
# ABSTRACT: Detect unquoted variable expansions that could split
our $VERSION = '0.004';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::UnquotedExpansion - detect unquoted $VAR that could word-split

=head1 DESCRIPTION

Scans the source text of a command for C<$VAR> / C<${VAR}> expansions
that are not inside double-quotes and whose next character is a path
delimiter (C</>, C<->, C<.>). Those are the classic word-splitting +
glob footguns:

    cat $HOME/.ssh/id_rsa       -> medium (UnquotedExpansion)
    rm -rf $TMPDIR/cache        -> medium

Note: this rule operates on raw source text, not on the AST. Quoted
strings and command substitutions are filtered heuristically, not
fully - expect some false negatives when expansion is buried inside
complex quoting.

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>.

=cut

sub check {
  my ( $class, $command ) = @_;

  my @issues;
  my $source = $command->{source} // '';

  my @unquoted_vars;
  while ( $source =~ m{(\$[a-zA-Z_][a-zA-Z0-9_]*)}g ) {
    my $var   = $1;
    my $start = pos($source) - length($var);

    # Skip expansions inside double-quotes — those do NOT word-split.
    # Walk the source left of $var and toggle a flag on each `"`.
    # Single-quoted regions are tracked separately and reset the toggle.
    my $in_dq = 0;
    my $in_sq = 0;
    for my $i ( 0 .. $start - 1 ) {
      my $ch = substr( $source, $i, 1 );
      if    ( $ch eq "'" && !$in_dq ) { $in_sq = !$in_sq; }
      elsif ( $ch eq '"' && !$in_sq ) { $in_dq = !$in_dq; }
      elsif ( $ch eq '\\' && !$in_sq ) { $i++ }
    }
    next if $in_dq || $in_sq;

    my $after = substr( $source, $start + length($var), 1 );
    if ( defined $after && $after =~ m{[/\-\.]} ) {
      push @unquoted_vars, $var;
    }
  }

  for my $var (@unquoted_vars) {
    push @issues, {
      rule     => 'UnquotedExpansion',
      severity => 'medium',
      message  => "Unquoted variable expansion may cause word splitting: $var",
      var      => $var,
      command  => $command->{command}
    };
  }

  return @issues;
}

1;