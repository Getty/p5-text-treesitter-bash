package Text::Treesitter::Bash::Security::Rule::ForkBomb;
# ABSTRACT: Detect the classic :(){ :|:& };: fork-bomb pattern
our $VERSION = '0.001';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::ForkBomb - flag the textbook fork-bomb function definition

=head1 DESCRIPTION

A fork-bomb is a one-line function that recursively spawns itself into
the background, exhausting the process table. The canonical Bash form
is:

    :(){ :|:& };:

The rule fires on any of these signals inside a function body:

=over 4

=item * a function whose name appears as a self-recursive call;

=item * the recursive call is dispatched in the background (C<&> or C<|&>);

=item * the call is a pipe (C<:|:>) or any subshell-recursive form.

=back

Implemented as a regex over the function source text because the
patterns are highly stereotyped and regex is robust against bash's many
whitespace / brace / semicolon placements.

=head1 EXAMPLES

    :(){ :|:& };:                            -> high
    bomb(){ bomb|bomb& }; bomb               -> high
    bash -c ':() { :|:& }; :'                -> high
    fork(){ (fork &) }; fork                 -> high
    harmless(){ echo hi; }; harmless         -> (not flagged)
    alias ll='ls -la'                        -> (not flagged)

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>.

=cut

# Two patterns:
#   (1) classical :(){ :|:& };:   — single char name, single pipe
#   (2) generic  name(){ ... name ...& ... }; name — any name
# We match the function-body slice, so the trailing ";:" / "; bomb" is
# the call-site and not strictly part of the body, but tree-sitter
# gives us the whole function_definition source, which includes it.

sub check {
  my ( $class, $command ) = @_;

  my $source = $command->{source} // q{};

  return unless $command->{function};
  return unless $source =~ m{\A([a-zA-Z0-9_]+|:)\s*\(\)\s*\{(.*)\}\z}s;

  my $name = $1;
  my $body = $2;

  # Self-recursion: the function name appears inside its own body.
  my $has_self_recursion = $body =~ /\Q$name\E/;

  # Backgrounding: pipe (`|`) or background operator (`&`) inside body.
  my $has_background = $body =~ /[|&]/;

  return unless $has_self_recursion && $has_background;

  return _forkbomb_issue( $command, $name, 'self-recursion with backgrounding' );
}

sub _forkbomb_issue {
  my ( $command, $name, $form ) = @_;
  return {
    rule     => 'ForkBomb',
    severity => 'high',
    message  => "Potential fork-bomb pattern ($name, $form)",
    command  => $command->{command} // $name,
    argv     => $command->{argv}    // [],
    source   => $command->{source}  // q{},
    function => 1,
  };
}

1;