package Text::Treesitter::Bash::Security::Rule::UnquotedExpansion;
# ABSTRACT: Detect unquoted variable expansions that could split
our $VERSION = '0.010';
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

The rule looks at the command's own text only (see
L<Text::Treesitter::Bash::Security::Rule/mask_source>), not at the AST.
Nothing inside quotes, escapes, comments, heredoc bodies or a nested
C<$(...)> counts (a nested command is reported once, for itself), and
neither does anything where Bash does not split words: the value of an
assignment (C<DIR=$HOME/bin>, C<export DIR=$HOME/bin>) and C<[[ ... ]]>.

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>.

=cut

sub check {
  my ( $class, $command ) = @_;

  my @issues;
  my $source = $command->{source} // '';

  # `[[ ... ]]` does not split words.
  return if $source =~ m/\A\s*\[\[/;

  # $words keeps the quotes of the command's own text, $unquoted has
  # everything inside quotes, escapes, nested substitutions, comments and
  # heredoc bodies blanked: what is left there is what the shell expands.
  my ( $words, $unquoted ) = $class->mask_source($source);

  # The value of an assignment is not split either: `DIR=$HOME/bin`,
  # `X=$HOME/y cmd` and the arguments of export / declare / local / ...
  my @assignment;
  my $declaring;
  while ( $words =~ m/(\S+)/g ) {
    my $word  = $1;
    my $end   = pos($words);
    my $start = $end - length $word;

    if ( $word =~ m/\A["']?[a-zA-Z_][a-zA-Z0-9_]*(?:\[[^\]]*\])?\+?=/ ) {
      push @assignment, [ $start, $end ];
    }
    elsif ( !$declaring && $word =~ m/\A(?:export|declare|typeset|local|readonly)\z/ ) {
      $declaring = 1;
    }
    elsif ( !( $declaring && $word =~ m/\A-/ ) ) {
      last;
    }
  }

  my @unquoted_vars;

  # Match all three bash expansion forms:
  #   $NAME            simple variable
  #   ${NAME[...]...}  braced variable (also ${NAME:-default}, ${NAME/pat/repl}, ...)
  #   $((expr))        arithmetic expansion
  # Each branch captures its own leading sigil so the reported `var`
  # field matches the source text the user sees (e.g. C<$bar>,
  # C<${HOME}>, C<$((1+2))>).
  my $rx = qr/
    (\$
    (?:
        \{[a-zA-Z_][a-zA-Z0-9_]*[^}]*\}
      | \(\(.+?\)\)
      | [a-zA-Z_][a-zA-Z0-9_]*
    ))
  /x;

  # Quoted text is blank in $unquoted, so everything found there is
  # unquoted by construction.
  while ( $unquoted =~ m{$rx}g ) {
    my $end   = pos($unquoted);
    my $start = $-[0];

    next if grep { $start >= $_->[0] && $start < $_->[1] } @assignment;

    # The character right after the WHOLE expansion (after `}` for
    # `${NAME}`, after `))` for `$((...))`, after the bare name for
    # `$NAME`) determines whether this is a path-context expansion —
    # the classic word-splitting + glob footgun shape.
    my $after = substr( $unquoted, $end, 1 );
    if ( $after =~ m{[/\-\.]} ) {
      # Report the text as written; the blanked copy only differs inside
      # `${...}` when that holds a quoted default.
      push @unquoted_vars, substr( $source, $start, $end - $start );
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