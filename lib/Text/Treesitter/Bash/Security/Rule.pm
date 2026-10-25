package Text::Treesitter::Bash::Security::Rule;
# ABSTRACT: Base class for security rules
our $VERSION = '0.003';
use strict;
use warnings;

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule - abstract base class for security rules

=head1 SYNOPSIS

    package Text::Treesitter::Bash::Security::Rule::YourRule;
    use parent 'Text::Treesitter::Bash::Security::Rule';

    sub check {
        my ( $class, $command ) = @_;
        return unless some_condition;
        return {
            rule     => 'YourRule',
            severity => 'low' | 'medium' | 'high',
            message  => 'Human-readable explanation',
        };
    }

    1;

=head1 DESCRIPTION

Every rule is a class with a single class-method C<check> that takes
one already-walked L<Text::Treesitter::Bash/commands> hashref and
returns zero, one, or many issue hashrefs.

=head1 CONTRACT

=head2 check

    my @issues = $class->check($command);

=over 4

=item B<$command> is a hashref as documented in L<Text::Treesitter::Bash/commands>.

=item B<Return value> may be:

=over 8

=item empty list - rule did not fire.

=item single hashref - one issue.

=item list of hashrefs - several distinct issues per command (rare; usually
when one command violates multiple sub-checks of the same rule).

=back

=back

The issue hashref MUST contain at least:

    {
        rule     => 'YourRule',
        severity => 'low' | 'medium' | 'high',
        message  => 'string',
    }

Rule-specific context fields (C<command>, C<arg>, C<source>, ...)
are encouraged but not required.

=head1 SEVERITY SCALE

=over 4

=item low - style / footgun, probably harmless but a code-smell.

=item medium - real risk under common conditions (e.g. unquoted
expansion in a path that may contain spaces).

=item high - likely exploit or data loss (e.g. C<rm -rf> of a
variable, C<LD_PRELOAD>, access to C</etc/shadow>).

=back

There is intentionally no C<critical> - criticality is a policy
decision above this layer.

=head1 CAVEATS

=over 4

=item Do not croak or die from C<check>. The checker treats C<check> as
total; an exception aborts the whole audit.

=item Do not print. Return structured data only.

=item Do not inspect the tree-sitter AST directly. The walker has
already extracted the fields you need. If a field is missing, extend
C<_command_entry> in L<Text::Treesitter::Bash>.

=back

=head1 HELPERS

=head2 mask_source

    my ( $words, $unquoted ) = $class->mask_source( $command->{source} );

For rules that match on the surface text of one command. Returns two
strings of the same length as the source, so a position in one is the
position in the other and in the source itself. Both leave out what is
not this command's own text:

=over 4

=item * the body of C<$(...)>, backticks, C<< <(...) >> and C<< >(...) >>
(those commands have an entry of their own), comments, and heredoc
bodies are blanked;

=item * inside single quotes, double quotes and C<$'...'>, whitespace and
the characters C<; & | ( ) E<lt> E<gt>> become C<\x01>, so a quoted
string stays one word.

=back

C<$words> keeps all other text, quotes included; match word-shaped things
(C<NAME=...>) on it. C<$unquoted> additionally blanks everything inside
quotes and every escaped character (C<\$HOME>), so what is left is text
the shell expands and splits; match expansions on it.

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Checker>.

=cut

sub check {
  my ( $class, $command ) = @_;
  die 'Abstract method check() must be implemented by subclass';
}

sub mask_source {
  my ( $class, $source ) = @_;

  $source //= q{};
  my $length = length $source;
  my ( $words, $unquoted ) = ( q{}, q{} );
  my ( $state, @heredocs ) = ('plain');
  my $index = 0;

  # Characters that would end a word outside of quotes.
  my $boundary = qr{[\s;&|()<>]};

  while ( $index < $length ) {
    my $char = substr( $source, $index, 1 );
    my $next = $index + 1 < $length ? substr( $source, $index + 1, 1 ) : q{};

    if ( $state eq 'plain' ) {
      if ( $char eq '\\' ) {
        # An escaped character is literal: no expansion, no word end.
        $words    .= $char . ( $next =~ $boundary ? "\x01" : $next );
        $unquoted .= q{  };
        $index += 2;
        next;
      }
      if ( $char eq q{'} || $char eq '"' ) {
        $state     = $char eq q{'} ? 'sq' : 'dq';
        $words    .= $char;
        $unquoted .= q{ };
        $index++;
        next;
      }
      if ( $char eq '$' && $next eq q{'} ) {
        $state     = 'ansi';
        $words    .= q{$'};
        $unquoted .= q{  };
        $index += 2;
        next;
      }
      if ( $char eq '`'
        || ( $char eq '$' && $next eq '(' && substr( $source, $index + 2, 1 ) ne '(' )
        || ( ( $char eq '<' || $char eq '>' ) && $next eq '(' ) )
      {
        my $end = _end_of_substitution( $source, $index );
        $words    .= q{ } x ( $end - $index );
        $unquoted .= q{ } x ( $end - $index );
        $index = $end;
        next;
      }
      if ( $char eq '#'
        && ( $index == 0 || substr( $source, $index - 1, 1 ) =~ m{[\s;&|(]} ) )
      {
        my $end = index( $source, "\n", $index );
        $end = $length if $end < 0;
        $words    .= q{ } x ( $end - $index );
        $unquoted .= q{ } x ( $end - $index );
        $index = $end;
        next;
      }
      if ( $char eq '<' && $next eq '<' && substr( $source, $index + 2, 1 ) ne '<' ) {
        pos($source) = $index;
        if ( $source =~ m{\G<<(-?)[ \t]*(?:'([^']*)'|"([^"]*)"|\\?([^\s;&|()<>]+))}gc ) {
          push @heredocs, [ $2 // $3 // $4, $1 ];
          my $end = pos($source);
          $words    .= substr( $source, $index, $end - $index );
          $unquoted .= substr( $source, $index, $end - $index );
          $index = $end;
          next;
        }
      }
      if ( $char eq "\n" && @heredocs ) {
        $words    .= "\n";
        $unquoted .= "\n";
        $index++;
        # The bodies follow the line in the order of their operators. A
        # body is text, not shell: blank it up to and with its delimiter.
        for my $heredoc (@heredocs) {
          my ( $delimiter, $dash ) = @$heredoc;
          while ( $index < $length ) {
            my $end = index( $source, "\n", $index );
            my $stop = $end < 0 ? $length : $end;
            my $line = substr( $source, $index, $stop - $index );
            $line =~ s{\A\t+}{} if $dash;
            my $blank = q{ } x ( $stop - $index );
            $words    .= $blank;
            $unquoted .= $blank;
            $index = $stop;
            if ( $end >= 0 ) {
              $words    .= "\n";
              $unquoted .= "\n";
              $index++;
            }
            last if $line eq $delimiter;
          }
        }
        @heredocs = ();
        next;
      }
      $words    .= $char;
      $unquoted .= $char;
      $index++;
      next;
    }

    # Inside quotes. Whitespace and operator characters do not end a word.
    if ( $char eq '\\' && $state ne 'sq' ) {
      $words    .= $char . ( $next =~ $boundary ? "\x01" : $next );
      $unquoted .= q{  };
      $index += 2;
      next;
    }
    if ( $state eq 'dq'
      && ( $char eq '`' || ( $char eq '$' && $next eq '(' && substr( $source, $index + 2, 1 ) ne '(' ) ) )
    {
      my $end = _end_of_substitution( $source, $index );
      $words    .= q{ } x ( $end - $index );
      $unquoted .= q{ } x ( $end - $index );
      $index = $end;
      next;
    }
    if ( $char eq ( $state eq 'dq' ? '"' : q{'} ) ) {
      $state     = 'plain';
      $words    .= $char;
      $unquoted .= q{ };
      $index++;
      next;
    }
    $words    .= $char =~ $boundary ? "\x01" : $char;
    $unquoted .= q{ };
    $index++;
  }

  # Escapes at the very end of the source can overshoot by one.
  return ( substr( $words, 0, $length ), substr( $unquoted, 0, $length ) );
}

# Index just past the substitution that starts at $start (`$(`, `<(`, `>(`
# or a backtick). Quotes and nested parentheses inside it are honoured;
# an unterminated one runs to the end of the source.
sub _end_of_substitution {
  my ( $source, $start ) = @_;

  my $length = length $source;

  if ( substr( $source, $start, 1 ) eq '`' ) {
    my $index = $start + 1;
    while ( $index < $length ) {
      my $char = substr( $source, $index, 1 );
      return $index + 1 if $char eq '`';
      $index += $char eq '\\' ? 2 : 1;
    }
    return $length;
  }

  my $depth = 0;
  my $index = $start + 1;    # on the `(`
  my $quote;

  while ( $index < $length ) {
    my $char = substr( $source, $index, 1 );

    if ( $char eq '\\' && ( $quote // q{} ) ne q{'} ) {
      $index += 2;
      next;
    }
    if ($quote) {
      undef $quote if $char eq $quote;
    }
    elsif ( $char eq q{'} || $char eq '"' ) {
      $quote = $char;
    }
    elsif ( $char eq '(' ) {
      $depth++;
    }
    elsif ( $char eq ')' ) {
      return $index + 1 if --$depth == 0;
    }
    $index++;
  }

  return $length;
}

1;