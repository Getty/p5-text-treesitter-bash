package Text::Treesitter::Bash::Security::Rule::PathTraversal;
# ABSTRACT: Detect path traversal patterns in commands
our $VERSION = '0.005';
use strict;
use warnings;
use parent 'Text::Treesitter::Bash::Security::Rule';

=encoding utf8

=head1 NAME

Text::Treesitter::Bash::Security::Rule::PathTraversal - detect path traversal and sensitive introspection

=head1 DESCRIPTION

Walks argv looking for two classes of paths:

=over 4

=item high - explicit traversal sequences: C<../>, C</etc/../>, C</proc/../>, C</sys/../>.

=item medium - introspective paths that can leak process / system state: C</proc/self>, C</proc/$$>, C</sys/fs>.

=back

=head1 SEE ALSO

L<Text::Treesitter::Bash::Security::Rule>,
L<Text::Treesitter::Bash::Security::Rule::SensitiveAccess>.

=cut

# (regex, message) pairs for the medium-severity introspection
# findings. The high-severity `..` match is checked separately because
# its regex is structurally different (no fixed prefix).
my @INTROSPECTION_PATTERNS = (
  [ qr{(?:^|/)proc/(?:self|\$\$)}, 'Process introspection path' ],
  [ qr{(?:^|/)sys/fs},           'sysfs path' ],
);

sub check {
  my ( $class, $command ) = @_;

  my @issues;

  for my $arg ( @{ $command->{argv} // [] } ) {
    next if ref $arg;

    # Match any `..` as a complete path segment — `/foo/../bar`, `../x`,
    # `/a/b/..`, `..` standalone. Anything inside a path that traverses
    # upward is a path traversal sign.
    if ( $arg =~ m{(?:^|/)\.\.(?:/|$)} ) {
      push @issues, {
        rule     => 'PathTraversal',
        severity => 'high',
        message  => "Path traversal detected: $arg",
        arg      => $arg,
        command  => $command->{command}
      };
    }

    for my $tuple (@INTROSPECTION_PATTERNS) {
      my ( $pattern, $prefix ) = @$tuple;
      if ( $arg =~ $pattern ) {
        push @issues, {
          rule     => 'PathTraversal',
          severity => 'medium',
          message  => "$prefix: $arg",
          arg      => $arg,
          command  => $command->{command}
        };
        last;
      }
    }
  }

  return @issues;
}

1;